//! Symmetric XOR frame cipher used by Shenzhen Beiying `WebEnfTool` on `ws://127.0.0.1:15071`.
//!
//! Verified from `WebEnfTool.exe` (`0x00459430`): Binary WebSocket frames carry UTF-8 JSON
//! XORed byte-for-byte with the repeating 18-byte ASCII key `b"BeiYing@ByTool2025"`.

use serde_json::Value;

/// 18-byte symmetric repeating XOR key verified at `0x00459430`.
pub const BEIYING_XOR_KEY: &[u8; 18] = b"BeiYing@ByTool2025";

/// Apply the Beiying XOR key in place (involution: calling twice restores original bytes).
pub fn xor_beiying_in_place(buf: &mut [u8]) {
    for (idx, byte) in buf.iter_mut().enumerate() {
        *byte ^= BEIYING_XOR_KEY[idx % BEIYING_XOR_KEY.len()];
    }
}

/// Serialize a JSON value as UTF-8 and XOR-encode it into a Binary WebSocket payload.
pub fn encode_json_binary(value: &Value) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = serde_json::to_vec(value)?;
    xor_beiying_in_place(&mut bytes);
    Ok(bytes)
}

/// XOR-decode a Binary WebSocket payload and parse it as UTF-8 JSON.
pub fn decode_json_binary(frame: &[u8]) -> Result<Value, serde_json::Error> {
    let mut plain = frame.to_vec();
    xor_beiying_in_place(&mut plain);
    serde_json::from_slice(&plain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn xor_involution_multi_block() {
        let original = b"BeiYing test payload longer than 18 bytes! 0123456789ABCDEF".to_vec();
        let mut work = original.clone();
        xor_beiying_in_place(&mut work);
        assert_ne!(work, original);
        assert_eq!(work[0], original[0] ^ b'B');
        assert_eq!(work[18], original[18] ^ b'B');
        xor_beiying_in_place(&mut work);
        assert_eq!(work, original);
    }

    #[test]
    fn json_binary_roundtrip_utf8() {
        let msg = json!({
            "Cmd": "ChangeDevice",
            "CmdId": 42,
            "Code": 0,
            "Data": {"Uuid": "010203040506", "Vid": 0x38ee, "Pid": 0x0016},
            "Message": "已经成功加载"
        });
        let encoded = encode_json_binary(&msg).expect("encode json");
        let decoded = decode_json_binary(&encoded).expect("decode json");
        assert_eq!(decoded, msg);
    }
}
