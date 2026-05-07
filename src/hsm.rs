use openssl::ssl::SslStream;
use std::error::Error;
use std::io::{Read, Write};
use std::net::TcpStream;

// Wrap a clear key with AES-CTR using the HSM master key stored in SLOT.
pub fn wrap_key_ctr(
    tls: &mut SslStream<TcpStream>,
    key: &[u8],
    slot: u8,
) -> Result<Vec<u8>, Box<dyn Error>> {
    check_slot(slot)?;
    aes_ctr_encrypt(tls, key, slot)
}

// Unwrap a wrapped key with AES-CTR using the HSM master key stored in SLOT.
pub fn unwrap_key_ctr(
    tls: &mut SslStream<TcpStream>,
    wrapped_key: &[u8],
    slot: u8,
) -> Result<Vec<u8>, Box<dyn Error>> {
    check_slot(slot)?;
    aes_ctr_decrypt(tls, wrapped_key, slot)
}

// Ask the HSM to AES-encrypt one 16-byte counter block.
// The returned block is used as CTR keystream.
fn aes_block_encrypt_hex(
    tls: &mut SslStream<TcpStream>,
    block: &[u8; 16],
    slot: u8,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let data_hex = hex::encode_upper(block);
    send_aes_command(tls, b'A', data_hex.as_bytes(), slot)
}

// Build and send the HSM command
fn send_aes_command(
    tls: &mut SslStream<TcpStream>,
    op: u8,
    data_hex: &[u8],
    slot: u8,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut cmd = Vec::new();

    cmd.push(op);
    cmd.push(b'4');
    cmd.extend_from_slice(format!("{:x}", slot).as_bytes());
    cmd.extend_from_slice(data_hex);
    cmd.extend_from_slice(b"\r\n");

    debugln!("sent: {}", String::from_utf8_lossy(&cmd));

    tls.write_all(&cmd)?;
    tls.flush()?;

    read_hsm_response(tls)
}

fn aes_ctr_encrypt(
    tls: &mut SslStream<TcpStream>,
    input: &[u8],
    slot: u8,
) -> Result<Vec<u8>, Box<dyn Error>> {
    use rand::RngCore;

    // 12 bytes de nonce aléatoire
    let mut counter = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut counter[..12]);

    // compteur initial = 0
    counter[12..].copy_from_slice(&0u32.to_be_bytes());

    let nonce = counter[..12].to_vec();

    let mut output = Vec::with_capacity(12 + input.len());

    // On préfixe le ciphertext avec le nonce.
    output.extend_from_slice(&nonce);

    for chunk in input.chunks(16) {
        let keystream_hex = aes_block_encrypt_hex(tls, &counter, slot)?;
        let keystream_text = std::str::from_utf8(&keystream_hex)?.trim();
        let keystream = hex::decode(keystream_text)?;

        for i in 0..chunk.len() {
            output.push(chunk[i] ^ keystream[i]);
        }

        increment_counter(&mut counter);
    }

    Ok(output)
}

fn aes_ctr_decrypt(
    tls: &mut SslStream<TcpStream>,
    input: &[u8],
    slot: u8,
) -> Result<Vec<u8>, Box<dyn Error>> {
    if input.len() < 12 {
        return Err("ciphertext too short".into());
    }

    let nonce = &input[..12];
    let ciphertext = &input[12..];

    let mut counter = [0u8; 16];
    counter[..12].copy_from_slice(nonce);
    counter[12..].copy_from_slice(&0u32.to_be_bytes());

    let mut output = Vec::with_capacity(ciphertext.len());

    for chunk in ciphertext.chunks(16) {
        let keystream_hex = aes_block_encrypt_hex(tls, &counter, slot)?;
        let keystream_text = std::str::from_utf8(&keystream_hex)?.trim();
        let keystream = hex::decode(keystream_text)?;

        for i in 0..chunk.len() {
            output.push(chunk[i] ^ keystream[i]);
        }

        increment_counter(&mut counter);
    }

    Ok(output)
}

fn check_slot(slot: u8) -> Result<(), Box<dyn Error>> {
    if slot > 3 {
        return Err("slot must be in [0, 3]".into());
    }

    Ok(())
}

fn increment_counter(counter: &mut [u8; 16]) {
    let mut n = u32::from_be_bytes([counter[12], counter[13], counter[14], counter[15]]);

    n += 1;

    counter[12..].copy_from_slice(&n.to_be_bytes());
}

fn read_hsm_response(tls: &mut SslStream<TcpStream>) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut buf = [0u8; 4096];
    let n = tls.read(&mut buf)?;

    if n == 0 {
        return Err("HSM closed connection".into());
    }

    Ok(buf[..n].to_vec())
}
