# `webenftool_linux`

Native Rust Linux replacement for the Shenzhen Beiying (`WebEnfTool.exe` v2.2.1.25) companion daemon used by BYTech / HubX keyboards such as the **Akko TAC75 HE (`38ee:0016`)**.

> **Note:** Native configuration and audio/screen-reactive lighting for Beiying (`Report ID 0x09`) keyboards are also integrated directly into `iot_driver_linux` (`iot_driver`). This standalone crate focuses on 1:1 WebSocket companion compatibility with the HubX web configurator (`https://demo.hubx.pro/keyboard/`) and lightweight standalone CLI audio streaming.

## Features

1. **HubX Web Configurator WebSocket Companion (`serve`)**:
   - Listens on `127.0.0.1:15071` (and `[::1]:15071` best-effort) with Chromium Private Network Access (`OPTIONS` preflight + `Access-Control-Allow-Private-Network: true`) and `Sec-WebSocket-Protocol` echo support.
   - Implements `GetFunctions` (`["Audion", "Cpu"]`), `ChangeDevice`, `GetSupportedEffects`, `GetEffectParamsAll`, `ChangeEffect`, `ChangeEffectParams`, and live `Push:ColorData` binary frames.
   - Automatically caches `<Uuid>.ini` layouts or falls back to the verified 83-key TAC75 HE layout + firmware `0xA1` (`getLedBeads`) discovery.
2. **Linux Audio Capture via PipeWire / PulseAudio**:
   - Captures the default output `.monitor` stream and computes a 256-band FFT spectrum in real time.
   - Drives per-key RGB and side lightbar LEDs directly over USB HID (`Report ID 0x09`).
3. **Standalone CLI Audio Visualizer (`audio`)**:
   - Streams audio-reactive lighting (`--mode 168`, etc.) without needing the web UI open.

## Verified Protocol Summary (`Report ID 0x09`)

- **WebSocket (`localhost:15071`)**:
  - **Text frames**: `"ping"` -> `"pong"`.
  - **Binary frames**: UTF-8 JSON XOR-masked with the 18-byte key `BeiYing@ByTool2025`.
  - **Envelope**: `{"Cmd", "CmdId", "Code", "Data", "Message"}`.
- **USB HID (`Report ID 0x09`, 64-byte wired Input/Output reports)**:
  - Descriptor-verified on vendor collections (`Usage Page >= 0xFF00`, `Report ID 0x09` In/Out 64B), never touching Rongyuan `send_feature_report` paths.
  - Trailer checksum at byte `63`: `!sum(pkt[0..63])`.
  - Handshake & capability queries: `0x82 0x01` (12-hex UUID), `0x87` (status), `0x82 0x0F` (LED protocol capability flags), `0xA1` (per-key LED bead matrix).
  - Supports all three per-key LED protocols (`0x08 0x01` RGB888, `0x08 0x03` dense RGB565, `0x08 0x04` grouped RGB565), clean off packet (`0x08 0x02`), side lightbar (`0x0E 0x01`/`0x02`), and optional `0x0B` telemetry.

## Build & Usage

```bash
cd webenftool_linux
cargo build --release
```

### 1. Passive Browser Preview (no `/dev/hidraw*` writes)

```bash
./target/release/webenftool-linux serve --dry-run --synthetic-audio
```

Open `https://demo.hubx.pro/keyboard/` and enable Music Rhythm to preview live `Push:ColorData` frames.

### 2. Real Hardware Web Companion (`demo.hubx.pro` + PipeWire/PulseAudio)

Ensure udev rules grant user access to `/dev/hidraw*` for `38ee:0016` (see `../udev/99-monsgeek-rebrands.rules`), then start:

```bash
RUST_LOG=info ./target/release/webenftool-linux serve
```

Keep it running while using `https://demo.hubx.pro/keyboard/`.

### 3. Standalone CLI Audio Mode

```bash
./target/release/webenftool-linux audio --mode 168 --brightness 100 --amplitude 600
```

## Running as a Background User Service (`systemd`)

To keep the WebSocket companion ready in the background on login (so `demo.hubx.pro` works without opening a terminal), run it as a **user** service (not `sudo`) so it has access to your PipeWire/PulseAudio audio session:

```bash
sudo install -D -m 755 target/release/webenftool-linux /usr/local/bin/webenftool-linux
mkdir -p ~/.config/systemd/user

cat << 'EOF' > ~/.config/systemd/user/webenftool.service
[Unit]
Description=WebEnfTool Linux Companion (BYTech / HubX Audio WebSocket)
After=pipewire-pulse.service pulseaudio.service

[Service]
ExecStart=/usr/local/bin/webenftool-linux serve
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable --now webenftool.service
```
