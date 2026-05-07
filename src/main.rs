use openssl::rand::rand_bytes;
use openssl::ssl::{SslConnector, SslMethod, SslOptions, SslStream, SslVerifyMode, SslVersion};
use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

#[macro_use]
mod debug;

mod hsm;

fn connect_hsm(
    host: &str,
    port: u16,
    sni: &str,
    identity: Option<&str>,
    psk_hex: Option<&str>,
) -> Result<SslStream<TcpStream>, Box<dyn std::error::Error>> {
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;

    builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

    builder.set_ciphersuites("TLS_AES_128_CCM_SHA256")?;
    builder.set_groups_list("P-256")?;

    builder.set_options(SslOptions::NO_TICKET);
    builder.set_verify(SslVerifyMode::NONE);

    // PSK authentication is optional.
    // It is enabled only when both identity and PSK are provided.
    if let (Some(identity), Some(psk_hex)) = (identity, psk_hex) {
        let psk = hex::decode(psk_hex)?;
        let identity = identity.as_bytes().to_vec();

        builder.set_psk_client_callback(move |_ssl, _hint, identity_buf, psk_buf| {
            if identity.len() > identity_buf.len() || psk.len() > psk_buf.len() {
                return Err(openssl::error::ErrorStack::get());
            }

            identity_buf[..identity.len()].copy_from_slice(&identity);
            psk_buf[..psk.len()].copy_from_slice(&psk);

            Ok(psk.len())
        });
    }

    let connector = builder.build();

    let tcp = TcpStream::connect((host, port))?;

    Ok(connector.connect(sni, tcp)?)
}

// Handle one local TCP client.
// Each client gets its own TLS connection to the remote keystore.
fn handle_client(
    mut client: TcpStream,
    host: String,
    port: u16,
    sni: String,
    identity: Option<String>,
    psk_hex: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut tls = connect_hsm(&host, port, &sni, identity.as_deref(), psk_hex.as_deref())?;

    let mut buf = [0u8; 4096];

    loop {
        let n = client.read(&mut buf)?;

        if n == 0 {
            return Ok(());
        }

        if n < 2 {
            client.write_all(b"ERR unknown command\n")?;
            continue;
        }

        let cmd = buf[0];
        // SLOT is the HSM master key slot used for wrap/unwrap.
        // Accepted slots are 0, 1, 2 and 3.
        let slot = match buf[1] {
            b'0'..=b'3' => buf[1] - b'0',
            _ => {
                client.write_all(b"ERR slot must be 0..3\n")?;
                continue;
            }
        };

        let payload_ascii = std::str::from_utf8(&buf[2..n])?.trim();
        let payload = hex::decode(payload_ascii)?;

        match cmd {
            b'W' => {
                let wrapped = hsm::wrap_key_ctr(&mut tls, &payload, slot)?;

                client.write_all(hex::encode_upper(&wrapped).as_bytes())?;
                client.write_all(b"\n")?;
            }

            b'U' => {
                let unwrapped = hsm::unwrap_key_ctr(&mut tls, &payload, slot)?;

                client.write_all(hex::encode_upper(&unwrapped).as_bytes())?;
                client.write_all(b"\n")?;
            }

            b'G' => {
                let mut key = [0u8; 32];
                rand_bytes(&mut key)?;

                let wrapped = hsm::wrap_key_ctr(&mut tls, &key, slot)?;

                client.write_all(hex::encode_upper(&key).as_bytes())?;
                client.write_all(b":")?;
                client.write_all(hex::encode_upper(&wrapped).as_bytes())?;
                client.write_all(b"\n")?;
            }

            _ => {
                client.write_all(b"ERR unknown command\n")?;
            }
        }

        client.flush()?;
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 5 {
        debugerr!(
            "usage: {} <local_port> <host> <remote_port> <sni> [identity] [psk_hex]",
            args[0]
        );

        std::process::exit(1);
    }

    let local_port: u16 = args[1].parse()?;

    // local_port < 2^16
    if local_port < 1024 {
        return Err("port must be >= 1024".into());
    }

    let host = args[2].clone();
    let remote_port: u16 = args[3].parse()?;
    let sni = args[4].clone();

    let identity = if args.len() >= 6 {
        Some(args[5].clone())
    } else {
        None
    };

    let psk_hex = if args.len() >= 7 {
        Some(args[6].clone())
    } else {
        None
    };

    let listener = TcpListener::bind(("127.0.0.1", local_port))?;

    for stream in listener.incoming() {
        match stream {
            Ok(client) => {
                let host = host.clone();
                let sni = sni.clone();
                let identity = identity.clone();
                let psk_hex = psk_hex.clone();

                // One thread per TCP client.
                // This allows multiple local clients to use the server at the same time.
                std::thread::spawn(move || {
                    if let Err(e) = handle_client(client, host, remote_port, sni, identity, psk_hex)
                    {
                        debugerr!("client error: {e}");
                    }
                });
            }

            Err(e) => {
                debugerr!("accept error: {e}");
            }
        }
    }

    Ok(())
}
