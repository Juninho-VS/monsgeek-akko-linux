//! JSON WebSocket command dispatcher, session management, and 33 FPS render loop.
//!
//! Emulates `WebEnfTool.exe` v2.2.1.25 (`ws://127.0.0.1:15071`) with symmetric
//! `b"BeiYing@ByTool2025"` XOR Binary frames and `"ping"` -> `"pong"` Text frames.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, broadcast, mpsc, watch};

use crate::audio::AudioEngine;
use crate::cipher::{decode_json_binary, encode_json_binary};
use crate::effects::{EffectParamStore, EffectRendererState};
use crate::hid_beiying::{
    BeiyingTransport, DryRunTransport, RealHidTransport, encode_push_color_data,
};
use crate::ini_config::{DeviceIniConfig, normalize_uuid, parse_int_auto, resolve_device_ini};
use crate::telemetry::TelemetryReader;
use crate::ws_codec::{WsError, WsFrame, accept_websocket, read_ws_frame, write_ws_frame};

pub const APP_VERSION: &str = "2.2.1.25";
pub const DEFAULT_WS_BIND: &str = "127.0.0.1:15071";

/// Runtime server options configured from CLI or tests.
#[derive(Debug, Clone)]
pub struct ServerOptions {
    pub dry_run: bool,
    pub synthetic_audio: bool,
    pub default_vid: u16,
    pub default_pid: u16,
    pub explicit_ini: Option<PathBuf>,
    pub allow_http_ini: bool,
    pub ignore_remote_quit: bool,
    pub persist_settings: bool,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            dry_run: false,
            synthetic_audio: false,
            default_vid: 0x38EE,
            default_pid: 0x0016,
            explicit_ini: None,
            allow_http_ini: true,
            ignore_remote_quit: false,
            persist_settings: true,
        }
    }
}

/// Persisted daemon settings (`~/.config/webenftool-linux/settings.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedSettings {
    pub lang: String,
    pub play_effect_row: bool,
    pub back_current: i32,
    pub lightbar_current: i32,
    pub effects: EffectParamStore,
}

impl Default for PersistedSettings {
    fn default() -> Self {
        Self {
            lang: "zh-CN".to_string(),
            play_effect_row: true,
            back_current: 180,
            lightbar_current: 500,
            effects: EffectParamStore::default(),
        }
    }
}

fn settings_file_path() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME")
        && !xdg.is_empty()
    {
        return PathBuf::from(xdg)
            .join("webenftool-linux")
            .join("settings.json");
    }
    if let Ok(home) = std::env::var("HOME")
        && !home.is_empty()
    {
        return PathBuf::from(home)
            .join(".config")
            .join("webenftool-linux")
            .join("settings.json");
    }
    PathBuf::from("webenftool-settings.json")
}

fn desktop_autostart_path() -> Option<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME")
        && !xdg.is_empty()
    {
        return Some(
            PathBuf::from(xdg)
                .join("autostart")
                .join("webenftool-linux.desktop"),
        );
    }
    if let Ok(home) = std::env::var("HOME")
        && !home.is_empty()
    {
        return Some(
            PathBuf::from(home)
                .join(".config")
                .join("autostart")
                .join("webenftool-linux.desktop"),
        );
    }
    None
}

fn load_settings(persist: bool) -> PersistedSettings {
    if !persist {
        return PersistedSettings::default();
    }
    let path = settings_file_path();
    fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_settings(persist: bool, settings: &PersistedSettings) {
    if !persist {
        return;
    }
    let path = settings_file_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(json_str) = serde_json::to_string_pretty(settings) {
        let _ = fs::write(path, json_str);
    }
}

/// Mutable state shared between WebSocket client handlers and the render loop.
pub struct AppState {
    pub opts: ServerOptions,
    pub settings: PersistedSettings,
    pub device_config: Option<DeviceIniConfig>,
    pub transport: Option<Arc<dyn BeiyingTransport>>,
    pub streaming_enabled: bool,
    pub dry_autostart: bool,
    pub renderer: EffectRendererState,
    pub needs_back_clear: bool,
    pub needs_lb_clear: bool,
    pub audio: AudioEngine,
    pub telemetry: TelemetryReader,
    pub push_tx: broadcast::Sender<Value>,
}

impl AppState {
    pub fn new(opts: ServerOptions, audio: AudioEngine, push_tx: broadcast::Sender<Value>) -> Self {
        let settings = load_settings(opts.persist_settings);
        Self {
            opts,
            settings,
            device_config: None,
            transport: None,
            streaming_enabled: false,
            dry_autostart: false,
            renderer: EffectRendererState::new(),
            needs_back_clear: false,
            needs_lb_clear: false,
            audio,
            telemetry: TelemetryReader::new(),
            push_tx,
        }
    }
}

/// Format standard `SendResult` envelope (`0x454b60..0x4559c0`).
fn send_result(cmd: &str, cmd_id: i64, code: i32, data: Value, msg: Option<&str>) -> Value {
    json!({
        "Cmd": cmd,
        "CmdId": if cmd_id != 0 { cmd_id } else { 999 },
        "Code": code,
        "Data": data,
        "Message": msg.map(Value::from).unwrap_or(Value::Null),
    })
}

fn parse_vid_pid_field(v: Option<&Value>, fallback: u16) -> u16 {
    let Some(val) = v else {
        return fallback;
    };
    if let Some(n) = val.as_u64() {
        return n as u16;
    }
    if let Some(s) = val.as_str()
        && let Some(parsed) = parse_int_auto(s)
    {
        return parsed as u16;
    }
    fallback
}

/// Handle a single decoded JSON request, returning `(response_json, shutdown_requested)`.
pub async fn dispatch_command(shared: &Arc<Mutex<AppState>>, req: &Value) -> (Value, bool) {
    let cmd = req.get("Cmd").and_then(Value::as_str).unwrap_or("NULL");
    let cmd_id = req.get("CmdId").and_then(Value::as_i64).unwrap_or(999);
    let data = req.get("Data");

    match cmd {
        "GetVersionInfo" => {
            let payload = json!({"Current": APP_VERSION, "Latest": APP_VERSION});
            (send_result(cmd, cmd_id, 0, payload, None), false)
        }
        "ChangeDevice" => {
            let Some(data_obj) = data.and_then(Value::as_object) else {
                return (
                    send_result(cmd, cmd_id, 6, Value::Null, Some("Data missing")),
                    false,
                );
            };
            let raw_uuid = data_obj.get("Uuid").and_then(Value::as_str).unwrap_or("");
            let uuid = normalize_uuid(raw_uuid);
            if uuid.is_empty() {
                return (
                    send_result(cmd, cmd_id, 6, Value::Null, Some("Data.Uuid missing")),
                    false,
                );
            }

            let (opts, prev_same) = {
                let st = shared.lock().await;
                let vid = parse_vid_pid_field(data_obj.get("Vid"), st.opts.default_vid);
                let pid = parse_vid_pid_field(data_obj.get("Pid"), st.opts.default_pid);
                let same = st.transport.as_ref().is_some_and(|t| {
                    let info = t.session_info();
                    info.vid == vid
                        && info.pid == pid
                        && (info.uuid.eq_ignore_ascii_case(&uuid) || uuid == "000000000000")
                });
                ((st.opts.clone(), vid, pid), same)
            };
            let (srv_opts, vid, pid) = opts;

            let transport_res: Result<Arc<dyn BeiyingTransport>, String> = if prev_same {
                let st = shared.lock().await;
                st.transport
                    .clone()
                    .ok_or_else(|| "missing transport".into())
            } else if srv_opts.dry_run {
                Ok(Arc::new(DryRunTransport::new(vid, pid, &uuid)))
            } else {
                let uuid_owned = uuid.clone();
                tokio::task::spawn_blocking(move || {
                    RealHidTransport::open(vid, pid, Some(&uuid_owned))
                        .map(|t| Arc::new(t) as Arc<dyn BeiyingTransport>)
                })
                .await
                .map_err(|e| format!("HID worker panicked: {e}"))
                .and_then(|r| r)
            };

            let transport = match transport_res {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!(error = %e, vid = format_args!("{:04X}", vid), pid = format_args!("{:04X}", pid), "ChangeDevice failed");
                    return (
                        send_result(
                            cmd,
                            cmd_id,
                            9,
                            Value::Null,
                            Some(&format!("未发现设备: {e}")),
                        ),
                        false,
                    );
                }
            };

            let side_light_avail = data_obj
                .get("SideLightAvailable")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let side_light_count = data_obj
                .get("SidelightCount")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize;

            let effective_uuid = if !transport.session_info().uuid.is_empty()
                && transport.session_info().uuid != "000000000000"
            {
                transport.session_info().uuid.clone()
            } else {
                uuid
            };

            let mut ini_cfg = match resolve_device_ini(
                &effective_uuid,
                srv_opts.explicit_ini.as_deref(),
                srv_opts.allow_http_ini,
            )
            .await
            {
                Ok((cfg, src)) => {
                    tracing::info!(uuid = %cfg.uuid, path = ?src, "Loaded device INI config");
                    cfg
                }
                Err(e) => {
                    tracing::warn!(uuid = %effective_uuid, error = %e, "Using built-in 75% fallback layout");
                    DeviceIniConfig::default_75_percent(&effective_uuid)
                }
            };
            if side_light_avail && side_light_count > 0 && ini_cfg.tape_count == 0 {
                ini_cfg.tape_count = side_light_count.min(255);
            }
            if ini_cfg.keymaps.is_empty() {
                transport.populate_led_beads(&mut ini_cfg);
            }

            let mut st = shared.lock().await;
            st.device_config = Some(ini_cfg);
            st.transport = Some(transport);
            if !prev_same {
                st.settings.back_current = 180;
                st.settings.lightbar_current = 500;
            }
            (
                send_result(cmd, cmd_id, 0, Value::Null, Some("已经成功加载")),
                false,
            )
        }
        "GetFunctions" => {
            let st = shared.lock().await;
            let funcs = if st.audio.available {
                json!(["Audion", "Cpu"])
            } else {
                json!(["Cpu"])
            };
            (send_result(cmd, cmd_id, 0, funcs, None), false)
        }
        "GetSupportedEffects" => {
            let mut st = shared.lock().await;
            if st.device_config.is_none() {
                return (
                    send_result(cmd, cmd_id, 2, Value::Null, Some("未初始化设备")),
                    false,
                );
            }
            if !st.audio.available {
                return (
                    send_result(cmd, cmd_id, 8, Value::Null, Some("未发现音频设备")),
                    false,
                );
            }
            let (back, lightbar) = st.device_config.as_ref().unwrap().split_effects();
            if !back.contains(&st.settings.back_current) {
                st.settings.back_current = 180;
            }
            if !lightbar.is_empty() && !lightbar.contains(&st.settings.lightbar_current) {
                st.settings.lightbar_current = 500;
            }
            // Match `0x4671d0`: calling GetSupportedEffects turns on live Push:ColorData streaming!
            st.streaming_enabled = true;

            let mut obj = serde_json::Map::new();
            obj.insert("Back".into(), json!(back));
            obj.insert("BackCurrent".into(), json!(st.settings.back_current));
            if !lightbar.is_empty() {
                obj.insert("LightBar".into(), json!(lightbar));
                obj.insert(
                    "LightBarCurrent".into(),
                    json!(st.settings.lightbar_current),
                );
            }
            (send_result(cmd, cmd_id, 0, Value::Object(obj), None), false)
        }
        "ChangeEffect" => {
            let mut st = shared.lock().await;
            if st.transport.is_none() {
                return (
                    send_result(cmd, cmd_id, 9, Value::Null, Some("未发现设备")),
                    false,
                );
            }
            if !st.audio.available {
                return (
                    send_result(cmd, cmd_id, 8, Value::Null, Some("未发现音频设备")),
                    false,
                );
            }
            let Some(cfg) = st.device_config.as_ref() else {
                return (
                    send_result(cmd, cmd_id, 7, Value::Null, Some("没找到配置的 ini")),
                    false,
                );
            };
            let Some(mode) = data
                .and_then(|d| d.get("Mode"))
                .and_then(Value::as_i64)
                .map(|m| m as i32)
            else {
                return (
                    send_result(cmd, cmd_id, 6, Value::Null, Some("Data.Mode invalid")),
                    false,
                );
            };
            if !cfg.supports_mode(mode) {
                return (
                    send_result(cmd, cmd_id, 10, Value::Null, Some("不支持的灯效模式")),
                    false,
                );
            }

            if mode >= 500 {
                if mode == 500 && st.settings.lightbar_current != 500 {
                    st.needs_lb_clear = true;
                }
                st.settings.lightbar_current = mode;
            } else {
                if mode == 180 && st.settings.back_current != 180 {
                    st.needs_back_clear = true;
                }
                st.settings.back_current = mode;
                if mode == 428
                    && let Some(ct) = data.and_then(|d| d.get("ColorTyp")).and_then(Value::as_i64)
                {
                    st.settings.effects.entry_mut(428).color_typ = (ct as i32).clamp(1, 21);
                    st.settings.effects.entry_mut(428).random_color = ct != 21;
                }
            }
            save_settings(st.opts.persist_settings, &st.settings);

            let push = json!({
                "Cmd": "Push:EffectChange",
                "Data": {
                    "BackCurrent": st.settings.back_current,
                    "LightBarCurrent": st.settings.lightbar_current,
                }
            });
            let _ = st.push_tx.send(push);
            (send_result(cmd, cmd_id, 0, Value::Null, None), false)
        }
        "GetEffectParams" => {
            let st = shared.lock().await;
            let mode = data
                .and_then(|d| d.get("Mode"))
                .and_then(Value::as_i64)
                .map(|m| m as i32)
                .unwrap_or(st.settings.back_current);
            let snap = st.audio.snapshot();
            let flat = st.settings.effects.build_flat_params(mode, snap.rms_db);
            (send_result(cmd, cmd_id, 0, flat, None), false)
        }
        "GetEffectParamsAll" => {
            let st = shared.lock().await;
            let Some(mode) = data
                .and_then(|d| d.get("Mode"))
                .and_then(Value::as_i64)
                .map(|m| m as i32)
                .or(Some(st.settings.back_current))
            else {
                return (
                    send_result(
                        cmd,
                        cmd_id,
                        6,
                        Value::Null,
                        Some("Data.Mode 必须是有效的灯效 ID"),
                    ),
                    false,
                );
            };
            let schema = st.settings.effects.build_params_schema(mode);
            (send_result(cmd, cmd_id, 0, schema, None), false)
        }
        "ChangeEffectParams" => {
            let mut st = shared.lock().await;
            let Some(obj) = data.and_then(Value::as_object) else {
                return (
                    send_result(cmd, cmd_id, 6, Value::Null, Some("Data missing")),
                    false,
                );
            };
            let mode = obj
                .get("Mode")
                .and_then(Value::as_i64)
                .map(|m| m as i32)
                .unwrap_or(st.settings.back_current);
            st.settings.effects.apply_patch(mode, obj);
            save_settings(st.opts.persist_settings, &st.settings);
            (send_result(cmd, cmd_id, 0, Value::Null, None), false)
        }
        "GetHardware" => {
            let st = shared.lock().await;
            let t = st.telemetry.sample();
            let hw = json!({
                "CpuLoad": t.cpu_load,
                "MemoryUsage": t.mem_usage,
                "CpuTemp": t.cpu_temp,
                "Volume": t.volume,
            });
            (send_result(cmd, cmd_id, 0, hw, None), false)
        }
        "GetAutoStart" => {
            let st = shared.lock().await;
            let enabled = if st.opts.dry_run {
                st.dry_autostart
            } else {
                desktop_autostart_path().is_some_and(|p| p.exists())
            };
            (send_result(cmd, cmd_id, 0, json!(enabled), None), false)
        }
        "SetAutoStart" => {
            let mut st = shared.lock().await;
            let enable = data.and_then(Value::as_bool).unwrap_or(false);
            if st.opts.dry_run {
                st.dry_autostart = enable;
            } else if let Some(path) = desktop_autostart_path() {
                if enable {
                    if let Some(parent) = path.parent() {
                        let _ = fs::create_dir_all(parent);
                    }
                    let exe = std::env::current_exe()
                        .ok()
                        .and_then(|p| p.to_str().map(str::to_string))
                        .unwrap_or_else(|| "webenftool-linux".to_string());
                    let entry = format!(
                        "[Desktop Entry]\nType=Application\nName=WebEnfTool Linux\nExec={exe} serve\nX-GNOME-Autostart-enabled=true\n"
                    );
                    let _ = fs::write(path, entry);
                } else {
                    let _ = fs::remove_file(path);
                }
            }
            (send_result(cmd, cmd_id, 0, json!(enable), None), false)
        }
        "GetLangs" => {
            let st = shared.lock().await;
            (
                send_result(cmd, cmd_id, 0, json!(st.settings.lang), None),
                false,
            )
        }
        "SetLangs" => {
            let mut st = shared.lock().await;
            let lang = data
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| "zh-CN".to_string());
            st.settings.lang = lang.clone();
            save_settings(st.opts.persist_settings, &st.settings);
            (send_result(cmd, cmd_id, 0, json!(lang), None), false)
        }
        "GetPlayEffectRow" => {
            let st = shared.lock().await;
            (
                send_result(cmd, cmd_id, 0, json!(st.settings.play_effect_row), None),
                false,
            )
        }
        "SetPlayEffectRow" => {
            let mut st = shared.lock().await;
            let row = data.and_then(Value::as_bool).unwrap_or(false);
            st.settings.play_effect_row = row;
            save_settings(st.opts.persist_settings, &st.settings);
            (send_result(cmd, cmd_id, 0, json!(row), None), false)
        }
        "re-start" => (send_result(cmd, cmd_id, 0, Value::Null, None), false),
        "quit" | "close" | "kill" => {
            let st = shared.lock().await;
            let should_stop = !st.opts.ignore_remote_quit;
            (send_result(cmd, cmd_id, 0, Value::Null, None), should_stop)
        }
        _ => (
            send_result(cmd, cmd_id, 6, Value::Null, Some("Unknown Cmd")),
            false,
        ),
    }
}

async fn accept_optional(
    listener: Option<&TcpListener>,
) -> std::io::Result<(TcpStream, std::net::SocketAddr)> {
    match listener {
        Some(l) => l.accept().await,
        None => std::future::pending().await,
    }
}

/// Bind and run the Beiying WebSocket server + 33 FPS render loop until shutdown signal.
pub async fn run_ws_server(
    bind_addr: &str,
    opts: ServerOptions,
    audio_source: Option<String>,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>), String> {
    let listener = TcpListener::bind(bind_addr)
        .await
        .map_err(|e| format!("Failed to bind WebSocket listener on {bind_addr}: {e}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| format!("Failed to query bound local addr: {e}"))?;
    let ipv6_listener =
        if !bind_addr.ends_with(":0") && local_addr.ip().is_loopback() && local_addr.is_ipv4() {
            let v6_addr = std::net::SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
                local_addr.port(),
            );
            match TcpListener::bind(v6_addr).await {
                Ok(l) => {
                    tracing::info!(addr = %v6_addr, "Also listening on IPv6 loopback");
                    Some(l)
                }
                Err(e) => {
                    tracing::debug!(addr = %v6_addr, error = %e, "IPv6 loopback bind skipped");
                    None
                }
            }
        } else {
            None
        };

    let audio = AudioEngine::start(audio_source.as_deref(), opts.synthetic_audio);
    let (push_tx, _) = broadcast::channel::<Value>(64);
    let shared = Arc::new(Mutex::new(AppState::new(opts, audio, push_tx)));

    let (shutdown_tx_internal, mut shutdown_rx_internal) = mpsc::channel::<()>(4);
    let shared_loop = Arc::clone(&shared);
    let mut external_shutdown = shutdown_rx.clone();

    let render_handle = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(30));
        let mut last_tick = Instant::now();
        let mut last_telemetry = Instant::now();

        loop {
            tokio::select! {
                _ = tick.tick() => {}
                _ = external_shutdown.changed() => {
                    if *external_shutdown.borrow() {
                        break;
                    }
                }
            }

            let dt = last_tick.elapsed().as_secs_f32().clamp(0.005, 0.1);
            last_tick = Instant::now();

            let mut st = shared_loop.lock().await;
            let Some(cfg) = st.device_config.clone() else {
                continue;
            };
            let Some(transport) = st.transport.clone() else {
                continue;
            };

            let back_mode = st.settings.back_current;
            let lb_mode = st.settings.lightbar_current;
            let back_clear = st.needs_back_clear;
            let lb_clear = st.needs_lb_clear;
            st.needs_back_clear = false;
            st.needs_lb_clear = false;

            let snap = st.audio.snapshot();
            let back_params = st.settings.effects.get(back_mode);
            let lb_params = st.settings.effects.get(lb_mode);

            let kb_frame = if back_mode != 180 {
                st.renderer
                    .render_keyboard(&cfg, back_mode, &back_params, &snap, dt)
            } else {
                Vec::new()
            };

            let lb_frame = if cfg.tape_count > 0 && lb_mode > 500 {
                st.renderer
                    .render_lightbar(cfg.tape_count, lb_mode, &lb_params, &snap)
            } else {
                Vec::new()
            };

            if (!kb_frame.is_empty() || back_clear) && st.streaming_enabled {
                let packed = encode_push_color_data(&kb_frame);
                let _ = st.push_tx.send(json!({
                    "Cmd": "Push:ColorData",
                    "Data": packed,
                }));
            }

            let telemetry_due =
                cfg.hardware_open && last_telemetry.elapsed() >= Duration::from_secs(1);
            let telemetry_pkt = if telemetry_due {
                last_telemetry = Instant::now();
                Some(st.telemetry.sample())
            } else {
                None
            };
            drop(st);

            if !kb_frame.is_empty() || back_clear {
                let _ = transport.send_keyboard_frame(&cfg, &kb_frame);
            }
            if !lb_frame.is_empty() || lb_clear {
                let _ = transport.send_lightbar_frame(&lb_frame);
            }
            if let Some(pkt) = telemetry_pkt {
                let _ = transport.send_telemetry(&pkt);
            }
        }
    });

    let mut accept_shutdown = shutdown_rx;
    let accept_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((stream, peer)) = accepted else {
                        break;
                    };
                    let st_clone = Arc::clone(&shared);
                    let quit_tx = shutdown_tx_internal.clone();
                    tokio::spawn(async move {
                        handle_client(stream, peer, st_clone, quit_tx).await;
                    });
                }
                accepted_v6 = accept_optional(ipv6_listener.as_ref()) => {
                    match accepted_v6 {
                        Ok((stream, peer)) => {
                            let st_clone = Arc::clone(&shared);
                            let quit_tx = shutdown_tx_internal.clone();
                            tokio::spawn(async move {
                                handle_client(stream, peer, st_clone, quit_tx).await;
                            });
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "IPv6 accept error");
                        }
                    }
                }
                _ = shutdown_rx_internal.recv() => {
                    tracing::info!("Shutdown requested via WebSocket command");
                    break;
                }
                _ = accept_shutdown.changed() => {
                    if *accept_shutdown.borrow() {
                        break;
                    }
                }
            }
        }
        render_handle.abort();
    });

    Ok((local_addr, accept_handle))
}

async fn handle_client(
    mut stream: TcpStream,
    peer: std::net::SocketAddr,
    shared: Arc<Mutex<AppState>>,
    quit_tx: mpsc::Sender<()>,
) {
    match accept_websocket(&mut stream).await {
        Ok(()) => {}
        Err(WsError::HttpHealthCheck) => return,
        Err(e) => {
            tracing::debug!(%peer, error = %e, "WebSocket handshake failed");
            return;
        }
    }

    tracing::info!(%peer, "WebSocket client connected");
    let (mut reader, mut writer) = stream.into_split();

    // Send immediate Push:VersionInfo on connect (`0x4585b0`)
    let push_version = json!({
        "Cmd": "Push:VersionInfo",
        "Data": {"Current": APP_VERSION, "Latest": APP_VERSION}
    });
    if let Ok(encoded) = encode_json_binary(&push_version)
        && write_ws_frame(&mut writer, &WsFrame::Binary(encoded))
            .await
            .is_err()
    {
        return;
    }

    let mut push_rx = {
        let st = shared.lock().await;
        st.push_tx.subscribe()
    };

    loop {
        tokio::select! {
            frame_res = read_ws_frame(&mut reader) => {
                match frame_res {
                    Ok(WsFrame::Text(txt)) => {
                        if txt.to_ascii_lowercase().contains("ping") {
                            let _ = write_ws_frame(&mut writer, &WsFrame::Text("pong".to_string())).await;
                        }
                    }
                    Ok(WsFrame::Binary(bytes)) => {
                        let req = match decode_json_binary(&bytes) {
                            Ok(v) => v,
                            Err(e) => {
                                tracing::warn!(%peer, error = %e, "Invalid JSON in XOR binary frame");
                                continue;
                            }
                        };
                        let (resp, should_quit) = dispatch_command(&shared, &req).await;
                        let cmd_name = req.get("Cmd").and_then(Value::as_str).unwrap_or("NULL");
                        let resp_code = resp.get("Code").and_then(Value::as_i64).unwrap_or(-1);
                        tracing::info!(%peer, cmd = %cmd_name, code = resp_code, "WS command handled");
                        if let Ok(encoded) = encode_json_binary(&resp)
                            && write_ws_frame(&mut writer, &WsFrame::Binary(encoded)).await.is_err()
                        {
                            break;
                        }
                        if should_quit {
                            let _ = quit_tx.send(()).await;
                            break;
                        }
                    }
                    Ok(WsFrame::Ping(p)) => {
                        if write_ws_frame(&mut writer, &WsFrame::Pong(p)).await.is_err() {
                            break;
                        }
                    }
                    Ok(WsFrame::Pong(_)) => {}
                    Ok(WsFrame::Close) | Err(_) => break,
                }
            }
            push_res = push_rx.recv() => {
                if let Ok(push_val) = push_res
                    && let Ok(encoded) = encode_json_binary(&push_val)
                    && write_ws_frame(&mut writer, &WsFrame::Binary(encoded)).await.is_err()
                {
                    break;
                }
            }
        }
    }

    tracing::info!(%peer, "WebSocket client disconnected");
}
