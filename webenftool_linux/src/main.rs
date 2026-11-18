//! `webenftool-linux` CLI entrypoint.
//!
//! Default subcommand (`serve`) binds `ws://127.0.0.1:15071` so `https://demo.hubx.pro/keyboard/`
//! works seamlessly on Linux with native PipeWire/PulseAudio `.monitor` audio-reactive lighting.
//! Standalone `audio` subcommand drives audio-reactive RGB directly without a browser.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;

use webenftool_linux::audio::AudioEngine;
use webenftool_linux::effects::{EffectRendererState, ModeParams, mode_name};
use webenftool_linux::hid_beiying::{BeiyingTransport, DryRunTransport, RealHidTransport};
use webenftool_linux::ini_config::{
    DeviceIniConfig, download_remote_ini, normalize_uuid, parse_int_auto, resolve_device_ini,
};
use webenftool_linux::protocol::{DEFAULT_WS_BIND, ServerOptions, run_ws_server};

#[derive(Parser)]
#[command(
    name = "webenftool-linux",
    version = "2.2.1.25",
    about = "Native Linux replacement for Beiying WebEnfTool.exe (Akko TAC75 HE / demo.hubx.pro)"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Start the WebSocket companion daemon on ws://127.0.0.1:15071 (default)
    Serve {
        /// TCP listen address
        #[arg(long, default_value = DEFAULT_WS_BIND)]
        bind: String,
        /// Simulate HID + config without touching /dev/hidraw*
        #[arg(long)]
        dry_run: bool,
        /// Generate synthetic audio energy when testing without playback
        #[arg(long)]
        synthetic_audio: bool,
        /// Default USB VID (hex or decimal)
        #[arg(long, default_value = "0x38ee")]
        vid: String,
        /// Default USB PID (hex or decimal)
        #[arg(long, default_value = "0x0016")]
        pid: String,
        /// Optional path to a pre-downloaded <Uuid>.ini file
        #[arg(long)]
        ini: Option<PathBuf>,
        /// Optional PulseAudio/PipeWire capture source name/substring
        #[arg(long)]
        audio_source: Option<String>,
        /// Disable remote HTTP <Uuid>.ini download fallback
        #[arg(long)]
        offline: bool,
    },
    /// Run standalone audio-reactive lighting directly from CLI without browser UI
    Audio {
        /// Effect mode ID (168..177, 428)
        #[arg(long, default_value_t = 168)]
        mode: i32,
        /// Hex color (#rrggbb) when --random-color is false
        #[arg(long, default_value = "#00ffcc")]
        color: String,
        /// Disable multi-color rainbow mode and use --color
        #[arg(long)]
        solid: bool,
        /// Brightness percent (0..100)
        #[arg(long, default_value_t = 100)]
        brightness: u8,
        /// Audio gain / amplitude (50..2000)
        #[arg(long, default_value_t = 500)]
        amplitude: i32,
        /// Animation speed (1..100)
        #[arg(long, default_value_t = 50)]
        speed: i32,
        /// Simulate HID writes without opening /dev/hidraw*
        #[arg(long)]
        dry_run: bool,
        /// Generate synthetic audio energy for testing
        #[arg(long)]
        synthetic_audio: bool,
        /// USB VID (hex or decimal)
        #[arg(long, default_value = "0x38ee")]
        vid: String,
        /// USB PID (hex or decimal)
        #[arg(long, default_value = "0x0016")]
        pid: String,
        /// Optional path to <Uuid>.ini
        #[arg(long)]
        ini: Option<PathBuf>,
        /// Optional PulseAudio/PipeWire capture source
        #[arg(long)]
        audio_source: Option<String>,
    },
    /// Download and inspect <Uuid>.ini from Beiying's config server
    FetchConfig {
        /// 12-hex-char device UUID (with or without 0x prefix)
        uuid: String,
    },
    /// List available PipeWire/PulseAudio capture sources
    ListAudio,
}

fn parse_u16_id(s: &str, fallback: u16) -> u16 {
    parse_int_auto(s)
        .filter(|&v| (0..=0xFFFF).contains(&v))
        .map(|v| v as u16)
        .unwrap_or(fallback)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let cli = Cli::parse();
    let cmd = cli.command.unwrap_or(Command::Serve {
        bind: DEFAULT_WS_BIND.to_string(),
        dry_run: false,
        synthetic_audio: false,
        vid: "0x38ee".to_string(),
        pid: "0x0016".to_string(),
        ini: None,
        audio_source: None,
        offline: false,
    });

    match cmd {
        Command::Serve {
            bind,
            dry_run,
            synthetic_audio,
            vid,
            pid,
            ini,
            audio_source,
            offline,
        } => {
            let opts = ServerOptions {
                dry_run,
                synthetic_audio,
                default_vid: parse_u16_id(&vid, 0x38EE),
                default_pid: parse_u16_id(&pid, 0x0016),
                explicit_ini: ini,
                allow_http_ini: !offline,
                ignore_remote_quit: false,
                persist_settings: true,
            };

            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let (bound_addr, handle) = run_ws_server(&bind, opts, audio_source, shutdown_rx)
                .await
                .map_err(anyhow::Error::msg)?;
            tracing::info!(
                addr = %bound_addr,
                dry_run,
                "webenftool-linux ready on ws://{bound_addr} (Ctrl+C to exit)"
            );

            tokio::select! {
                _ = handle => {}
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("Ctrl+C received, shutting down...");
                    let _ = shutdown_tx.send(true);
                }
            }
        }
        Command::Audio {
            mode,
            color,
            solid,
            brightness,
            amplitude,
            speed,
            dry_run,
            synthetic_audio,
            vid,
            pid,
            ini,
            audio_source,
        } => {
            let vid_u16 = parse_u16_id(&vid, 0x38EE);
            let pid_u16 = parse_u16_id(&pid, 0x0016);
            let transport: Box<dyn BeiyingTransport> = if dry_run {
                Box::new(DryRunTransport::new(vid_u16, pid_u16, "000000000000"))
            } else {
                Box::new(
                    RealHidTransport::open(vid_u16, pid_u16, None).map_err(anyhow::Error::msg)?,
                )
            };
            let uuid = transport.session_info().uuid.clone();
            let cfg = match resolve_device_ini(&uuid, ini.as_deref(), true).await {
                Ok((c, _)) => c,
                Err(_) => DeviceIniConfig::default_75_percent(&uuid),
            };

            let audio = AudioEngine::start(audio_source.as_deref(), synthetic_audio);
            let mut params = ModeParams::default_for_mode(mode);
            params.color = color;
            params.random_color = !solid;
            params.brightness_percent = brightness.min(100);
            params.amplitude = amplitude;
            params.animation_speed = speed.clamp(1, 100);

            tracing::info!(
                mode,
                name = %mode_name(mode),
                audio_source = %audio.source_name,
                device = %transport.session_info().path,
                "Running standalone audio-reactive lighting (Ctrl+C to stop & clear)"
            );

            let mut renderer = EffectRendererState::new();
            let mut tick = tokio::time::interval(Duration::from_millis(30));
            let mut last = Instant::now();
            let ctrl_c = tokio::signal::ctrl_c();
            tokio::pin!(ctrl_c);

            loop {
                tokio::select! {
                    _ = &mut ctrl_c => {
                        let _ = transport.send_keyboard_frame(&cfg, &[]);
                        break;
                    }
                    _ = tick.tick() => {
                        let dt = last.elapsed().as_secs_f32().clamp(0.005, 0.1);
                        last = Instant::now();
                        let snap = audio.snapshot();
                        let frame = renderer.render_keyboard(&cfg, mode, &params, &snap, dt);
                        if let Err(e) = transport.send_keyboard_frame(&cfg, &frame) {
                            tracing::error!(error = %e, "HID frame write failed");
                            break;
                        }
                    }
                }
            }
        }
        Command::FetchConfig { uuid } => {
            let norm = normalize_uuid(&uuid);
            let content = download_remote_ini(&norm)
                .await
                .map_err(anyhow::Error::msg)?;
            let parsed = DeviceIniConfig::parse(&norm, &content);
            println!(
                "Fetched {norm}.ini ({} bytes): modes={:?}, keys={}, tape_count={}, hardware_open={}",
                content.len(),
                parsed.supported_modes,
                parsed.all_keys.len(),
                parsed.tape_count,
                parsed.hardware_open
            );
        }
        Command::ListAudio => {
            let sources = webenftool_linux::audio::list_sources().map_err(anyhow::Error::msg)?;
            for s in sources {
                let tag = if s.is_monitor { "[monitor]" } else { "[input]" };
                println!("{tag} {} -- {}", s.name, s.description);
            }
        }
    }

    Ok(())
}
