# KEWU
KEWU (Key Encapsulation Wrap/Unwrap) is a simple CLI tool to wrap and unwrap and generate cryptographic keys in Rust using a remote keystore based on https://github.com/purien/keystore

KEWU uses:
-AES CTR
-TLS 1.3

## Install Rust

Follow the official Rust installation guide: https://doc.rust-lang.org/book/ch01-01-installation.html

## Build 
```bash
cargo build --release
```

## Run

Format:
```bash
cargo run -- <local_port> <host> <remote_port> <sni> [identity] [psk_hex]
```

Example:
```
cargo run -- 9000 host.org 7786 sni.com Client_identity AABBCCDDEEFF00112233445566778899
```


## Wrap Key

Format: `W[SLOT][KEY_HEX]` 
- W = wrap key
- SLOT = HSM master key slot used for wrapping
- KEY_HEX = clear key encoded in hex

Response: `WRAPPED_KEY_HEX`

Example: 
```
W1ABCD236478C34569
6024303DB9AD833FCAFDC0ED1A009AB53999CF9A
```

## Unwrap Key

Format: `U[SLOT][WRAPPED_KEY_HEX]` 

Response: `CLEAR_KEY_HEX`

Example: 
```
U16024303DB9AD833FCAFDC0ED1A009AB53999CF9A
ABCD236478C34569
```

## Generate Key
Format: `G[SLOT]`

Response: `CLEAR_KEY_HEX:WRAPPED_KEY_HEX`

Example: 
```
G1
EFC6F89050A3E71A1D2A86B658C7C8D75A01B82B7C4A4760514DF291A0C3A1A2:6FD30CDC0213761ADAD33FEF9FDEF7551C8574ACC2E9166F65BEC90B35AF004F799CA6BB1C03A6144B971054
```

## Errors

Invalid slot: `ERR slot must be 0..3`

Invalid command: `ERR unknown command`

## TLS Configuration

KEWU opens a TLS 1.3 connection to the remote keystore.

Configuration:
- TLS_AES_128_CCM_SHA256
- P-256
- TLS1.3
- NO_TICKET
- Server certificate verification is disabled.
- Optional PSK authentication is supported.