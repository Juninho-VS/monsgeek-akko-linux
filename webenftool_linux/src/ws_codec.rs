//! Minimal async RFC 6455 WebSocket server codec over `tokio::io`.
//!
//! Uses `httparse` for HTTP upgrade parsing, inline RFC 3174 SHA-1 for `Sec-WebSocket-Accept`,
//! and `base64` for header encoding. Avoids pulling in extra WebSocket crates outside the cache.

use std::io;

use base64::Engine as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_HTTP_HEADER_BYTES: usize = 8 * 1024;
const MAX_WS_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// Decoded WebSocket frame variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsFrame {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close,
}

/// Errors emitted during HTTP upgrade or WebSocket frame parsing.
#[derive(Debug, thiserror::Error)]
pub enum WsError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("HTTP handshake malformed or incomplete")]
    InvalidHandshake,
    #[error("Plain HTTP GET handled")]
    HttpHealthCheck,
    #[error("Frame exceeds maximum allowed payload size ({0} bytes)")]
    FrameTooLarge(usize),
    #[error("Protocol violation: {0}")]
    Protocol(&'static str),
}

/// Compute the 20-byte RFC 3174 SHA-1 digest of `input`.
pub fn sha1_digest(input: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xEFCD_AB89;
    let mut h2: u32 = 0x98BA_DCFE;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xC3D2_E1F0;

    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(input.len() + 72);
    padded.extend_from_slice(input);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 80];
    for chunk in padded.as_chunks::<64>().0 {
        for (i, &word_bytes) in chunk.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(word_bytes);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDCu32),
                _ => (b ^ c ^ d, 0xCA62_C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

/// Compute `Sec-WebSocket-Accept` from client `Sec-WebSocket-Key`.
pub fn compute_accept_key(client_key: &str) -> String {
    let mut combined = String::with_capacity(client_key.len() + WS_GUID.len());
    combined.push_str(client_key.trim());
    combined.push_str(WS_GUID);
    let digest = sha1_digest(combined.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(digest)
}

/// Perform the server-side RFC 6455 HTTP upgrade handshake.
///
/// If a plain HTTP `GET` request arrives without `Upgrade: websocket`, replies with `200 OK`
/// JSON service metadata and returns `Err(WsError::HttpHealthCheck)`.
pub async fn accept_websocket<S>(stream: &mut S) -> Result<(), WsError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 512];
    let header_end = loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(WsError::InvalidHandshake);
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > MAX_HTTP_HEADER_BYTES {
            return Err(WsError::InvalidHandshake);
        }
    };

    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(&buf[..header_end]) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return Err(WsError::InvalidHandshake),
    }

    let mut is_upgrade = false;
    let mut ws_key: Option<&str> = None;
    let mut ws_protocol: Option<&str> = None;
    for h in req.headers.iter() {
        if h.name.eq_ignore_ascii_case("upgrade")
            && std::str::from_utf8(h.value)
                .map(|v| v.eq_ignore_ascii_case("websocket"))
                .unwrap_or(false)
        {
            is_upgrade = true;
        } else if h.name.eq_ignore_ascii_case("sec-websocket-key")
            && let Ok(val) = std::str::from_utf8(h.value)
        {
            ws_key = Some(val);
        } else if h.name.eq_ignore_ascii_case("sec-websocket-protocol")
            && let Ok(val) = std::str::from_utf8(h.value)
        {
            let first = val.split(',').next().map(str::trim).unwrap_or("");
            if !first.is_empty() && !first.contains(['\r', '\n']) {
                ws_protocol = Some(first);
            }
        }
    }

    if req
        .method
        .is_some_and(|m| m.eq_ignore_ascii_case("OPTIONS"))
    {
        let resp = "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: *\r\nAccess-Control-Allow-Private-Network: true\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(resp.as_bytes()).await?;
        stream.flush().await?;
        return Err(WsError::HttpHealthCheck);
    }

    if !is_upgrade || ws_key.is_none() {
        let body = r#"{"service":"webenftool-linux","version":"2.2.1.25"}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Private-Network: true\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(resp.as_bytes()).await?;
        stream.flush().await?;
        return Err(WsError::HttpHealthCheck);
    }

    let accept = compute_accept_key(ws_key.unwrap_or_default());
    let proto_hdr = ws_protocol
        .map(|p| format!("Sec-WebSocket-Protocol: {p}\r\n"))
        .unwrap_or_default();
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n{proto_hdr}\r\n"
    );
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

/// Read a single logical WebSocket message (reassembling fragmented frames if `FIN == 0`).
pub async fn read_ws_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<WsFrame, WsError> {
    let mut fragmented_opcode: Option<u8> = None;
    let mut assembled: Vec<u8> = Vec::new();

    loop {
        let mut head = [0u8; 2];
        match reader.read_exact(&mut head).await {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(WsFrame::Close),
            Err(e) => return Err(WsError::Io(e)),
        }

        let fin = (head[0] & 0x80) != 0;
        let opcode = head[0] & 0x0F;
        let masked = (head[1] & 0x80) != 0;
        let len_code = head[1] & 0x7F;

        let payload_len: usize = match len_code {
            126 => {
                let mut ext = [0u8; 2];
                reader.read_exact(&mut ext).await?;
                u16::from_be_bytes(ext) as usize
            }
            127 => {
                let mut ext = [0u8; 8];
                reader.read_exact(&mut ext).await?;
                let raw = u64::from_be_bytes(ext);
                if raw > MAX_WS_FRAME_BYTES as u64 {
                    return Err(WsError::FrameTooLarge(MAX_WS_FRAME_BYTES));
                }
                raw as usize
            }
            n => n as usize,
        };

        if payload_len > MAX_WS_FRAME_BYTES || assembled.len() + payload_len > MAX_WS_FRAME_BYTES {
            return Err(WsError::FrameTooLarge(payload_len));
        }

        let mask_key = if masked {
            let mut key = [0u8; 4];
            reader.read_exact(&mut key).await?;
            Some(key)
        } else {
            None
        };

        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            reader.read_exact(&mut payload).await?;
            if let Some(key) = mask_key {
                for (i, b) in payload.iter_mut().enumerate() {
                    *b ^= key[i & 3];
                }
            }
        }

        // Control frames (Close=0x8, Ping=0x9, Pong=0xA) can be interleaved inside fragmented data.
        match opcode {
            0x8 => return Ok(WsFrame::Close),
            0x9 => return Ok(WsFrame::Ping(payload)),
            0xA => return Ok(WsFrame::Pong(payload)),
            0x1 | 0x2 => {
                if fragmented_opcode.is_some() {
                    return Err(WsError::Protocol(
                        "new data frame before continuation finished",
                    ));
                }
                if fin {
                    return decode_data_frame(opcode, payload);
                }
                fragmented_opcode = Some(opcode);
                assembled.extend_from_slice(&payload);
            }
            0x0 => {
                let orig =
                    fragmented_opcode.ok_or(WsError::Protocol("unexpected continuation frame"))?;
                assembled.extend_from_slice(&payload);
                if fin {
                    return decode_data_frame(orig, assembled);
                }
            }
            _ => return Err(WsError::Protocol("unsupported WebSocket opcode")),
        }
    }
}

fn decode_data_frame(opcode: u8, payload: Vec<u8>) -> Result<WsFrame, WsError> {
    match opcode {
        0x1 => {
            let text = String::from_utf8(payload)
                .map_err(|_| WsError::Protocol("invalid UTF-8 in Text frame"))?;
            Ok(WsFrame::Text(text))
        }
        0x2 => Ok(WsFrame::Binary(payload)),
        _ => Err(WsError::Protocol("invalid data opcode")),
    }
}

/// Encode and write an unmasked server-to-client WebSocket frame.
pub async fn write_ws_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &WsFrame,
) -> Result<(), io::Error> {
    let (opcode, payload): (u8, &[u8]) = match frame {
        WsFrame::Text(s) => (0x1, s.as_bytes()),
        WsFrame::Binary(b) => (0x2, b.as_slice()),
        WsFrame::Ping(b) => (0x9, b.as_slice()),
        WsFrame::Pong(b) => (0xA, b.as_slice()),
        WsFrame::Close => (0x8, &[]),
    };

    let mut header = Vec::with_capacity(10);
    header.push(0x80 | opcode);
    let len = payload.len();
    if len < 126 {
        header.push(len as u8);
    } else if len <= u16::MAX as usize {
        header.push(126);
        header.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        header.push(127);
        header.extend_from_slice(&(len as u64).to_be_bytes());
    }

    writer.write_all(&header).await?;
    if !payload.is_empty() {
        writer.write_all(payload).await?;
    }
    writer.flush().await
}

/// Helper to build a client-masked frame (primarily for unit/integration tests).
pub fn encode_client_masked_frame(opcode: u8, fin: bool, payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(14 + payload.len());
    out.push(if fin { 0x80 | opcode } else { opcode });
    let len = payload.len();
    if len < 126 {
        out.push(0x80 | (len as u8));
    } else if len <= u16::MAX as usize {
        out.push(0x80 | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0x80 | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    out.extend_from_slice(&mask);
    for (i, b) in payload.iter().enumerate() {
        out.push(b ^ mask[i & 3]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6455_accept_key_vector() {
        assert_eq!(
            compute_accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[tokio::test]
    async fn decode_masked_and_fragmented_frames() {
        let mask = [0x37, 0xFA, 0x21, 0x3D];
        // Short text frame "ping"
        let frame1 = encode_client_masked_frame(0x1, true, b"ping", mask);
        // Medium binary frame (> 126 bytes)
        let med_payload = vec![0xABu8; 300];
        let frame2 = encode_client_masked_frame(0x2, true, &med_payload, mask);
        // Fragmented text frame "hello" + " world"
        let mut frame3 = encode_client_masked_frame(0x1, false, b"hello", mask);
        frame3.extend_from_slice(&encode_client_masked_frame(0x0, true, b" world", mask));

        let mut stream = Vec::new();
        stream.extend_from_slice(&frame1);
        stream.extend_from_slice(&frame2);
        stream.extend_from_slice(&frame3);

        let mut cursor = std::io::Cursor::new(stream);
        assert_eq!(
            read_ws_frame(&mut cursor).await.unwrap(),
            WsFrame::Text("ping".into())
        );
        assert_eq!(
            read_ws_frame(&mut cursor).await.unwrap(),
            WsFrame::Binary(med_payload)
        );
        assert_eq!(
            read_ws_frame(&mut cursor).await.unwrap(),
            WsFrame::Text("hello world".into())
        );
        assert_eq!(read_ws_frame(&mut cursor).await.unwrap(), WsFrame::Close);
    }
}
