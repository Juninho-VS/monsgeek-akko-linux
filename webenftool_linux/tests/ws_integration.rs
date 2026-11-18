//! Passive end-to-end WebSocket protocol test over loopback in `--dry-run` + synthetic audio mode.

use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::watch;

use webenftool_linux::cipher::{decode_json_binary, encode_json_binary};
use webenftool_linux::protocol::{ServerOptions, run_ws_server};
use webenftool_linux::ws_codec::{WsFrame, encode_client_masked_frame, read_ws_frame};

const TEST_MASK: [u8; 4] = [0x12, 0x34, 0x56, 0x78];

async fn send_client_cmd(writer: &mut tokio::net::tcp::OwnedWriteHalf, req: &Value) {
    let encoded = encode_json_binary(req).expect("encode xor json");
    let frame = encode_client_masked_frame(0x2, true, &encoded, TEST_MASK);
    writer
        .write_all(&frame)
        .await
        .expect("write ws binary frame");
}

async fn recv_next_json(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    expected_cmd: Option<&str>,
) -> Value {
    for _ in 0..32 {
        let frame = tokio::time::timeout(Duration::from_secs(3), read_ws_frame(reader))
            .await
            .expect("ws read timed out")
            .expect("ws read error");
        if let WsFrame::Binary(bytes) = frame {
            let val = decode_json_binary(&bytes).expect("decode xor json");
            let cmd = val.get("Cmd").and_then(Value::as_str).unwrap_or("");
            if let Some(want) = expected_cmd
                && cmd != want
            {
                continue;
            }
            return val;
        }
    }
    panic!(
        "Did not receive expected WebSocket JSON command {:?}",
        expected_cmd
    );
}

#[tokio::test]
async fn end_to_end_beiying_ws_flow_dry_run() {
    let opts = ServerOptions {
        dry_run: true,
        synthetic_audio: true,
        allow_http_ini: false,
        persist_settings: false,
        ignore_remote_quit: true,
        ..ServerOptions::default()
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (addr, server_task) = run_ws_server("127.0.0.1:0", opts, None, shutdown_rx)
        .await
        .expect("server bind");

    let stream = TcpStream::connect(addr).await.expect("tcp connect");
    let (raw_read, mut writer) = stream.into_split();
    let mut reader = BufReader::new(raw_read);

    // 1. RFC 6455 HTTP upgrade
    let hs = format!(
        "GET / HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    writer.write_all(hs.as_bytes()).await.unwrap();
    let mut header_buf = String::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        header_buf.push_str(&line);
        if header_buf.ends_with("\r\n\r\n") {
            break;
        }
    }
    assert!(header_buf.contains("101 Switching Protocols"));
    assert!(header_buf.contains("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));

    // Drain any already-buffered bytes? read_line stopped at \r\n\r\n so read_ws_frame reads straight from BufReader!
    // 2. Expect immediate Push:VersionInfo
    let push_ver = recv_next_json(&mut reader, Some("Push:VersionInfo")).await;
    assert_eq!(push_ver["Data"]["Current"], "2.2.1.25");

    // 3. Ping -> Pong text heartbeat
    let ping_frame = encode_client_masked_frame(0x1, true, b"ping", TEST_MASK);
    writer.write_all(&ping_frame).await.unwrap();
    let pong = read_ws_frame(&mut reader).await.unwrap();
    assert_eq!(pong, WsFrame::Text("pong".to_string()));

    // 4. GetFunctions MUST work BEFORE ChangeDevice (web client checks "Audion" first!)
    send_client_cmd(&mut writer, &json!({"Cmd": "GetFunctions", "CmdId": 1})).await;
    let fn_res = recv_next_json(&mut reader, Some("GetFunctions")).await;
    assert_eq!(fn_res["Code"], 0);
    assert!(
        fn_res["Data"]
            .as_array()
            .unwrap()
            .contains(&json!("Audion"))
    );

    // 5. ChangeDevice (Akko TAC75 HE VID/PID, dry-run fallback)
    send_client_cmd(
        &mut writer,
        &json!({
            "Cmd": "ChangeDevice",
            "CmdId": 2,
            "Data": {
                "Uuid": "0x010203040506",
                "Vid": 0x38EE,
                "Pid": 0x0016,
                "ConnectType": "USB",
                "WirelessDedicatedSupported": false
            }
        }),
    )
    .await;
    let dev_res = recv_next_json(&mut reader, Some("ChangeDevice")).await;
    assert_eq!(dev_res["Code"], 0);
    assert_eq!(dev_res["Message"], "已经成功加载");

    // 6. GetSupportedEffects (enables live Push:ColorData)
    send_client_cmd(
        &mut writer,
        &json!({"Cmd": "GetSupportedEffects", "CmdId": 3}),
    )
    .await;
    let fx_res = recv_next_json(&mut reader, Some("GetSupportedEffects")).await;
    assert_eq!(fx_res["Code"], 0);
    assert_eq!(fx_res["Data"]["BackCurrent"], 180);
    assert!(
        fx_res["Data"]["Back"]
            .as_array()
            .unwrap()
            .contains(&json!(168))
    );

    // 7. GetEffectParamsAll (Modes 168 & 428)
    send_client_cmd(
        &mut writer,
        &json!({"Cmd": "GetEffectParamsAll", "CmdId": 4, "Data": {"Mode": 168}}),
    )
    .await;
    let schema168 = recv_next_json(&mut reader, Some("GetEffectParamsAll")).await;
    assert_eq!(schema168["Code"], 0);
    assert_eq!(schema168["Data"]["SchemaVersion"], 1);
    assert_eq!(schema168["Data"]["Name"], "音频轻舞");

    // 8. ChangeEffect -> Mode 168 + ChangeEffectParams -> check Push:ColorData streams!
    send_client_cmd(
        &mut writer,
        &json!({"Cmd": "ChangeEffect", "CmdId": 5, "Data": {"Mode": 168}}),
    )
    .await;
    let chg_res = recv_next_json(&mut reader, Some("ChangeEffect")).await;
    assert_eq!(chg_res["Code"], 0);

    send_client_cmd(
        &mut writer,
        &json!({
            "Cmd": "ChangeEffectParams",
            "CmdId": 6,
            "Data": {"Mode": 168, "BrightnessPercent": 90, "Amplitude": 900}
        }),
    )
    .await;
    let chg_p_res = recv_next_json(&mut reader, Some("ChangeEffectParams")).await;
    assert_eq!(chg_p_res["Code"], 0);

    // Wait for a non-empty live Push:ColorData binary frame driven by synthetic audio
    let mut got_non_empty = false;
    for _ in 0..15 {
        let color_push = recv_next_json(&mut reader, Some("Push:ColorData")).await;
        if color_push["Data"].as_array().is_some_and(|a| !a.is_empty()) {
            got_non_empty = true;
            break;
        }
    }
    assert!(
        got_non_empty,
        "expected non-empty live Push:ColorData visualizer frame within 15 ticks"
    );

    // Also verify PNA OPTIONS preflight and Sec-WebSocket-Protocol echo
    let mut opt_stream = TcpStream::connect(addr).await.expect("connect options");
    opt_stream
        .write_all(
            format!("OPTIONS / HTTP/1.1\r\nHost: {addr}\r\nAccess-Control-Request-Private-Network: true\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut opt_reader = BufReader::new(opt_stream);
    let mut opt_hdr = String::new();
    loop {
        let mut line = String::new();
        if opt_reader.read_line(&mut line).await.unwrap() == 0 {
            break;
        }
        opt_hdr.push_str(&line);
        if opt_hdr.ends_with("\r\n\r\n") {
            break;
        }
    }
    assert!(opt_hdr.contains("204 No Content"));
    assert!(opt_hdr.contains("Access-Control-Allow-Private-Network: true"));

    let mut sub_stream = TcpStream::connect(addr).await.expect("connect subproto");
    sub_stream
        .write_all(
            format!(
                "GET / HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: bytech, json\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut sub_reader = BufReader::new(sub_stream);
    let mut sub_hdr = String::new();
    loop {
        let mut line = String::new();
        sub_reader.read_line(&mut line).await.unwrap();
        sub_hdr.push_str(&line);
        if sub_hdr.ends_with("\r\n\r\n") {
            break;
        }
    }
    assert!(sub_hdr.contains("101 Switching Protocols"));
    assert!(sub_hdr.contains("Sec-WebSocket-Protocol: bytech"));

    let _ = shutdown_tx.send(true);
    let _ = server_task.await;
}
