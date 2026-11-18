//! Beiying audio-reactive effect parameter state, `GetEffectParamsAll` JSON schema
//! builder, and real-time per-key + side-lightbar RGB frame renderer.
//!
//! Verified against `WebEnfTool.exe` (`0x461200..0x464470`, `0x467730`, `0x45da50..0x45e910`).

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::audio::AudioSnapshot;
use crate::ini_config::DeviceIniConfig;

/// Canonical parameters for a single lighting mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeParams {
    pub color: String,
    pub random_color: bool,
    pub brightness_percent: u8,
    pub gamma: f64,
    pub animation_speed: i32,
    pub trigger_threshold: i32,
    pub splash_width_percent: i32,
    pub amplitude: i32,
    pub sample_minimum: i32,
    pub sample_maximum: i32,
    pub rhythm_mode: i32,
    pub color_typ: i32,
}

impl ModeParams {
    /// Return verified default parameters for `mode` (`0x461bfe..0x463c5d`).
    pub fn default_for_mode(mode: i32) -> Self {
        Self {
            color: if mode == 177 {
                "#950ede".to_string()
            } else {
                "#ff0000".to_string()
            },
            random_color: true,
            brightness_percent: 100,
            gamma: 2.2,
            animation_speed: match mode {
                169 | 173 => 1,
                171 => 2,
                172 => 20,
                177 => 80,
                _ => 50,
            },
            trigger_threshold: if mode == 176 { 5 } else { 10 },
            splash_width_percent: 60,
            amplitude: match mode {
                176 => 28,
                172 => 180,
                177 => 616,
                _ => 500,
            },
            sample_minimum: 1,
            sample_maximum: 255,
            rhythm_mode: 2,
            color_typ: 1,
        }
    }
}

/// Return exact UI display name from `WebEnfTool.exe` (`0x46134b..0x461550`).
pub fn mode_name(mode: i32) -> String {
    match mode {
        168 => "音频轻舞".to_string(),
        169 => "光彩夺目".to_string(),
        170 => "云起雪飞".to_string(),
        171 => "光场变化".to_string(),
        172 => "溪水滔滔".to_string(),
        173 => "百花争艳".to_string(),
        174 => "正弦".to_string(),
        175 => "彩色链条".to_string(),
        176 => "水花".to_string(),
        177 => "脉冲频谱".to_string(),
        428 => "动态频谱".to_string(),
        180 | 500 => "关闭".to_string(),
        501..=510 => format!("侧灯 {}", mode - 500),
        _ => format!("Effect {mode}"),
    }
}

/// Persisted user effect parameters keyed by mode ID.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EffectParamStore {
    pub per_mode: BTreeMap<i32, ModeParams>,
}

impl EffectParamStore {
    pub fn get(&self, mode: i32) -> ModeParams {
        self.per_mode
            .get(&mode)
            .cloned()
            .unwrap_or_else(|| ModeParams::default_for_mode(mode))
    }

    pub fn entry_mut(&mut self, mode: i32) -> &mut ModeParams {
        self.per_mode
            .entry(mode)
            .or_insert_with(|| ModeParams::default_for_mode(mode))
    }

    /// Apply partial `ChangeEffectParams` JSON keys (including `0x45df30` legacy aliases).
    pub fn apply_patch(&mut self, mode: i32, obj: &Map<String, Value>) {
        let p = self.entry_mut(mode);

        if let Some(c) = obj.get("Color").and_then(Value::as_str)
            && is_valid_hex_color(c)
        {
            p.color = c.to_ascii_lowercase();
        }
        if let Some(rc) = obj
            .get("RandomColor")
            .or_else(|| obj.get("MoreColor"))
            .and_then(value_as_bool)
        {
            p.random_color = rc;
            if mode == 428 && !rc {
                p.color_typ = 21;
            } else if mode == 428 && rc && p.color_typ == 21 {
                p.color_typ = 1;
            }
        }
        if let Some(br) = obj
            .get("BrightnessPercent")
            .or_else(|| obj.get("Brightness"))
            .or_else(|| obj.get("BrilLance"))
            .and_then(value_as_f64)
        {
            p.brightness_percent = br.clamp(0.0, 100.0).round() as u8;
        }
        if let Some(g) = obj.get("Gamma").and_then(value_as_f64) {
            p.gamma = g.clamp(0.0, 3.0);
        }
        if let Some(spd) = obj
            .get("AnimationSpeed")
            .or_else(|| obj.get("Speed"))
            .and_then(value_as_i32)
        {
            p.animation_speed = spd.clamp(1, 100);
        }
        if let Some(thr) = obj.get("TriggerThreshold").and_then(value_as_i32) {
            p.trigger_threshold = thr.clamp(1, 100);
        }
        if let Some(sw) = obj.get("SplashWidthPercent").and_then(value_as_i32) {
            p.splash_width_percent = sw.clamp(40, 150);
        }
        if let Some(amp) = obj
            .get("Amplitude")
            .or_else(|| obj.get("Amp"))
            .and_then(value_as_i32)
        {
            let max_amp = if mode == 176 { 100 } else { 2000 };
            let min_amp = if mode == 176 { 10 } else { 50 };
            p.amplitude = amp.clamp(min_amp, max_amp);
        }
        if let Some(smin) = obj.get("SampleMinimum").and_then(value_as_i32) {
            p.sample_minimum = smin.clamp(1, 254);
        }
        if let Some(smax) = obj.get("SampleMaximum").and_then(value_as_i32) {
            p.sample_maximum = smax.clamp(2, 255);
        }
        if p.sample_minimum >= p.sample_maximum {
            p.sample_maximum = (p.sample_minimum + 1).min(255);
            if p.sample_minimum >= p.sample_maximum {
                p.sample_minimum = p.sample_maximum - 1;
            }
        }
        if let Some(rm) = obj.get("RhythmMode").and_then(value_as_i32) {
            p.rhythm_mode = rm.clamp(0, 2);
        }
        if let Some(ct) = obj
            .get("ColorTyp")
            .or_else(|| obj.get("Pattern"))
            .and_then(value_as_i32)
        {
            p.color_typ = ct.clamp(1, 21);
            if mode == 428 {
                p.random_color = ct != 21;
            }
        }
    }

    /// Build `GetEffectParams` flat JSON object (`0x467730`).
    pub fn build_flat_params(&self, mode: i32, current_db: i32) -> Value {
        let p = self.get(mode);
        let mut obj = Map::new();
        obj.insert("Mode".into(), json!(mode));
        obj.insert("Color".into(), json!(p.color));
        obj.insert("RandomColor".into(), json!(p.random_color));
        obj.insert("Brightness".into(), json!(p.brightness_percent));
        obj.insert("BrightnessPercent".into(), json!(p.brightness_percent));
        obj.insert("Gamma".into(), json!(p.gamma));
        obj.insert("Speed".into(), json!(p.animation_speed));
        obj.insert("AnimationSpeed".into(), json!(p.animation_speed));
        obj.insert("Amplitude".into(), json!(p.amplitude));
        obj.insert("TriggerThreshold".into(), json!(p.trigger_threshold));
        obj.insert("SplashWidthPercent".into(), json!(p.splash_width_percent));
        obj.insert("Db".into(), json!(current_db));
        if matches!(mode, 168 | 170 | 428) {
            obj.insert("SampleMinimum".into(), json!(p.sample_minimum));
            obj.insert("SampleMaximum".into(), json!(p.sample_maximum));
        }
        if mode == 177 {
            obj.insert("RhythmMode".into(), json!(p.rhythm_mode));
        }
        if mode == 428 {
            obj.insert("ColorTyp".into(), json!(p.color_typ));
        }
        Value::Object(obj)
    }

    /// Build schema-driven `GetEffectParamsAll` descriptor (`SchemaVersion: 1`, `0x461200..0x464470`).
    pub fn build_params_schema(&self, mode: i32) -> Value {
        let p = self.get(mode);
        let def = ModeParams::default_for_mode(mode);
        let mut controls: Vec<Value> = Vec::new();
        let mut values = Map::new();

        if mode != 180 && mode != 500 {
            push_control(
                &mut controls,
                &mut values,
                mode,
                "Color",
                "颜色",
                "color",
                json!(0),
                json!(0),
                0.0,
                json!(p.color),
                json!(def.color),
                Vec::new(),
            );
            push_control(
                &mut controls,
                &mut values,
                mode,
                "RandomColor",
                "多色模式",
                "switch",
                json!(0),
                json!(1),
                0.0,
                json!(p.random_color),
                json!(if mode == 428 {
                    p.color_typ != 21
                } else {
                    def.random_color
                }),
                Vec::new(),
            );
            push_control(
                &mut controls,
                &mut values,
                mode,
                "BrightnessPercent",
                "亮度",
                "slider",
                json!(0),
                json!(100),
                1.0,
                json!(p.brightness_percent),
                json!(def.brightness_percent),
                Vec::new(),
            );
            push_control(
                &mut controls,
                &mut values,
                mode,
                "Gamma",
                "伽马校正（0关闭）",
                "slider",
                json!(0.0),
                json!(2.2),
                0.1,
                json!(p.gamma),
                json!(def.gamma),
                Vec::new(),
            );

            if mode != 176 {
                let is_trigger = mode == 174;
                push_control(
                    &mut controls,
                    &mut values,
                    mode,
                    "AnimationSpeed",
                    if is_trigger {
                        "触发阈值"
                    } else {
                        "动画速度"
                    },
                    "slider",
                    json!(1),
                    json!(100),
                    1.0,
                    json!(p.animation_speed),
                    json!(def.animation_speed),
                    Vec::new(),
                );
            }

            if mode == 174 || mode == 176 {
                push_control(
                    &mut controls,
                    &mut values,
                    mode,
                    "TriggerThreshold",
                    if mode == 176 {
                        "触发灵敏度"
                    } else {
                        "触发阈值"
                    },
                    "slider",
                    json!(1),
                    json!(100),
                    1.0,
                    json!(p.trigger_threshold),
                    json!(def.trigger_threshold),
                    Vec::new(),
                );
            }

            if mode == 176 {
                push_control(
                    &mut controls,
                    &mut values,
                    mode,
                    "SplashWidthPercent",
                    "水花宽度比例（%）",
                    "slider",
                    json!(40),
                    json!(150),
                    1.0,
                    json!(p.splash_width_percent),
                    json!(def.splash_width_percent),
                    Vec::new(),
                );
            }

            if (168..=177).contains(&mode) || mode == 428 {
                let (amp_label, amp_min, amp_max) = if mode == 176 {
                    ("扩散速度", 10, 100)
                } else {
                    ("振幅", 50, 2000)
                };
                push_control(
                    &mut controls,
                    &mut values,
                    mode,
                    "Amplitude",
                    amp_label,
                    "slider",
                    json!(amp_min),
                    json!(amp_max),
                    1.0,
                    json!(p.amplitude.clamp(amp_min, amp_max)),
                    json!(def.amplitude),
                    Vec::new(),
                );
            }

            if matches!(mode, 168 | 170 | 428) {
                push_control(
                    &mut controls,
                    &mut values,
                    mode,
                    "SampleMinimum",
                    "采样频段下限",
                    "slider",
                    json!(1),
                    json!(254),
                    1.0,
                    json!(p.sample_minimum),
                    json!(def.sample_minimum),
                    Vec::new(),
                );
                push_control(
                    &mut controls,
                    &mut values,
                    mode,
                    "SampleMaximum",
                    "采样频段上限",
                    "slider",
                    json!(2),
                    json!(255),
                    1.0,
                    json!(p.sample_maximum),
                    json!(def.sample_maximum),
                    Vec::new(),
                );
            }

            if mode == 177 {
                let rhythm_opts = vec![
                    json!({"Name": "节奏峰值", "Value": 0}),
                    json!({"Name": "节奏脉冲", "Value": 1}),
                    json!({"Name": "节奏均值", "Value": 2}),
                ];
                push_control(
                    &mut controls,
                    &mut values,
                    mode,
                    "RhythmMode",
                    "节奏模式",
                    "select",
                    json!(0),
                    json!(2),
                    1.0,
                    json!(p.rhythm_mode),
                    json!(def.rhythm_mode),
                    rhythm_opts,
                );
            }

            if mode == 428 {
                let color_opts: Vec<Value> = (1..=20)
                    .map(|idx| json!({"Name": format!("Preset {idx}"), "Value": idx}))
                    .collect();
                push_control(
                    &mut controls,
                    &mut values,
                    mode,
                    "ColorTyp",
                    "颜色模式",
                    "select",
                    json!(1),
                    json!(20),
                    1.0,
                    json!(p.color_typ.clamp(1, 20)),
                    json!(1),
                    color_opts,
                );
            }
        }

        let constraints = if matches!(mode, 168 | 170 | 428) {
            vec![json!({
                "Left": "SampleMinimum",
                "Operator": "<",
                "Right": "SampleMaximum"
            })]
        } else {
            Vec::new()
        };

        json!({
            "SchemaVersion": 1,
            "Mode": mode,
            "Name": mode_name(mode),
            "Controls": controls,
            "Values": Value::Object(values),
            "SetCommand": "ChangeEffectParams",
            "Constraints": constraints
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn push_control(
    controls: &mut Vec<Value>,
    values: &mut Map<String, Value>,
    mode: i32,
    key: &str,
    label: &str,
    ctrl_type: &str,
    min: Value,
    max: Value,
    step: f64,
    value: Value,
    default: Value,
    options: Vec<Value>,
) {
    values.insert(key.to_string(), value.clone());
    controls.push(json!({
        "Key": key,
        "Name": label,
        "ControlId": format!("effect_{mode}_{key}"),
        "ControlType": ctrl_type,
        "Min": min,
        "Max": max,
        "Step": step,
        "Value": value,
        "Default": default,
        "Options": options
    }));
}

fn value_as_bool(v: &Value) -> Option<bool> {
    v.as_bool().or_else(|| v.as_i64().map(|n| n != 0))
}

fn value_as_i32(v: &Value) -> Option<i32> {
    v.as_i64()
        .map(|n| n as i32)
        .or_else(|| v.as_f64().map(|f| f.round() as i32))
}

fn value_as_f64(v: &Value) -> Option<f64> {
    v.as_f64().or_else(|| v.as_i64().map(|n| n as f64))
}

fn is_valid_hex_color(s: &str) -> bool {
    let hex = s.strip_prefix('#').unwrap_or(s);
    hex.len() == 6 && hex.chars().all(|c| c.is_ascii_hexdigit())
}

fn parse_hex_rgb(s: &str) -> [u8; 3] {
    let hex = s.strip_prefix('#').unwrap_or(s);
    if hex.len() != 6 {
        return [255, 0, 0];
    }
    let r = u8::from_str_radix(&hex[0..2], 16).unwrap_or(255);
    let g = u8::from_str_radix(&hex[2..4], 16).unwrap_or(0);
    let b = u8::from_str_radix(&hex[4..6], 16).unwrap_or(0);
    [r, g, b]
}

/// Real-time animation state across ~30 FPS render ticks.
#[derive(Debug, Default)]
pub struct EffectRendererState {
    phase: f32,
    peak_caps: Vec<f32>,
    sparkles: HashMap<u16, (f32, f32)>, // key_id -> (intensity, hue)
    ripples: Vec<(f32, f32)>,           // (radius, hue)
    prev_beat: f32,
    rng_state: u32,
}

impl EffectRendererState {
    pub fn new() -> Self {
        Self {
            rng_state: 0x1357_2468,
            ..Self::default()
        }
    }

    fn next_rand(&mut self) -> f32 {
        let mut x = self.rng_state;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.rng_state = x;
        (x as f32) / (u32::MAX as f32)
    }

    /// Render the keyboard key matrix (`Vec<(key_id, [R, G, B])>`) for `mode` and `audio`.
    pub fn render_keyboard(
        &mut self,
        cfg: &DeviceIniConfig,
        mode: i32,
        params: &ModeParams,
        audio: &AudioSnapshot,
        dt_secs: f32,
    ) -> Vec<(u16, [u8; 3])> {
        if mode == 180 || cfg.all_keys.is_empty() {
            return Vec::new();
        }

        let speed_scale = 0.25 + (params.animation_speed.max(1) as f32 / 50.0);
        self.phase = (self.phase + dt_secs * speed_scale * 2.5) % 3600.0;

        let amp_gain = (params.amplitude as f32 / 500.0).clamp(0.15, 4.0);
        let threshold = (params.trigger_threshold as f32 / 120.0).clamp(0.02, 0.85);
        let bands = audio.slice_bands(
            params.sample_minimum,
            params.sample_maximum,
            cfg.num_cols.max(8),
        );
        let scaled_bands: Vec<f32> = bands
            .iter()
            .map(|&v| (v * amp_gain).clamp(0.0, 1.0))
            .collect();
        let energy = (audio.rhythm_energy(params.rhythm_mode) * amp_gain).clamp(0.0, 1.0);
        let base_rgb = parse_hex_rgb(&params.color);

        if self.peak_caps.len() != cfg.num_cols {
            self.peak_caps = vec![0.0; cfg.num_cols];
        }
        for (cap, &b) in self.peak_caps.iter_mut().zip(scaled_bands.iter()) {
            *cap = if b > *cap {
                b
            } else {
                (*cap - dt_secs * 1.4).max(0.0)
            };
        }

        // Update transient pools for sparkle (173) and splash ripples (176)
        if mode == 173 {
            self.sparkles.retain(|_, (int, _)| {
                *int -= dt_secs * speed_scale * 1.8;
                *int > 0.02
            });
            if energy > threshold {
                let spawn_count = ((energy - threshold) * 8.0).ceil() as usize;
                for _ in 0..spawn_count.min(6) {
                    let idx = (self.next_rand() * cfg.all_keys.len() as f32) as usize
                        % cfg.all_keys.len();
                    let hue = (self.phase * 40.0 + self.next_rand() * 360.0) % 360.0;
                    self.sparkles.insert(cfg.all_keys[idx].key_id, (1.0, hue));
                }
            }
        } else if mode == 176 {
            let diff_speed = 0.5 + (params.amplitude as f32 / 35.0);
            for (r, _) in &mut self.ripples {
                *r += dt_secs * diff_speed;
            }
            self.ripples.retain(|(r, _)| *r < 1.35);
            let onset = audio.rhythm_pulse * amp_gain;
            if onset > threshold && onset > self.prev_beat * 1.05 {
                let hue = (self.phase * 65.0) % 360.0;
                self.ripples.push((0.0, hue));
            }
            self.prev_beat = onset;
        }

        let mut frame = Vec::with_capacity(cfg.all_keys.len());
        let rows_f = cfg.num_rows.max(1) as f32;

        for kp in &cfg.all_keys {
            let col_level = scaled_bands
                .get(kp.col % scaled_bands.len())
                .copied()
                .unwrap_or(0.0);
            // Normalized bottom-up height `0.0` (bottom row) .. `1.0` (top row)
            let row_from_bottom = 1.0 - kp.y_norm;
            let dx = kp.x_norm - 0.5;
            let dy = kp.y_norm - 0.5;
            let radial = (dx * dx + dy * dy).sqrt() * 1.42; // ~0.0 center .. 1.0 corners

            let (raw_rgb, intensity) = match mode {
                // 168: 音频轻舞 — Classic bottom-up spectrum columns + falling peak cap
                168 => {
                    let bar =
                        ((col_level * (rows_f + 0.5)) - row_from_bottom * rows_f).clamp(0.0, 1.0);
                    let cap_pos = self.peak_caps[kp.col];
                    let cap =
                        if (row_from_bottom - cap_pos).abs() < (0.8 / rows_f) && cap_pos > 0.05 {
                            1.0
                        } else {
                            0.0
                        };
                    let lvl = bar.max(cap);
                    let col = if params.random_color {
                        hsv_to_rgb((kp.x_norm * 240.0 + self.phase * 25.0) % 360.0, 0.95, 1.0)
                    } else {
                        base_rgb
                    };
                    (col, lvl)
                }
                // 169: 光彩夺目 — Center-outward radial bloom
                169 => {
                    let lvl = ((energy * 1.25 - radial) * 2.5).clamp(0.0, 1.0);
                    let col = if params.random_color {
                        hsv_to_rgb((radial * 180.0 + self.phase * 45.0) % 360.0, 0.95, 1.0)
                    } else {
                        base_rgb
                    };
                    (col, lvl)
                }
                // 170: 云起雪飞 — Center-mirrored vertical EQ symmetric around middle row
                170 => {
                    let mid_dist = (kp.y_norm - 0.5).abs() * 2.0;
                    let lvl = ((col_level - mid_dist) * 2.2).clamp(0.0, 1.0);
                    let col = if params.random_color {
                        hsv_to_rgb(
                            (mid_dist * 120.0 + kp.x_norm * 180.0 + self.phase * 30.0) % 360.0,
                            0.9,
                            1.0,
                        )
                    } else {
                        base_rgb
                    };
                    (col, lvl)
                }
                // 171: 光场变化 — Ambient color wave modulated by global beat energy
                171 => {
                    let wave = 0.5 + 0.5 * (kp.x_norm * 4.0 + self.phase * 1.5).sin();
                    let lvl = (0.12 + energy * 0.88) * (0.4 + 0.6 * wave);
                    let col = if params.random_color {
                        hsv_to_rgb((kp.x_norm * 360.0 + self.phase * 35.0) % 360.0, 0.92, 1.0)
                    } else {
                        base_rgb
                    };
                    (col, lvl)
                }
                // 172: 溪水滔滔 — Flowing horizontal stream accelerated by audio level
                172 => {
                    let stream =
                        ((kp.x_norm * 3.0 + kp.y_norm * 0.6 - self.phase * (1.2 + energy)).sin()
                            * 0.5
                            + 0.5)
                            * (0.2 + 0.8 * energy);
                    let col = if params.random_color {
                        hsv_to_rgb(
                            (175.0 + kp.x_norm * 80.0 + self.phase * 20.0) % 360.0,
                            0.9,
                            1.0,
                        )
                    } else {
                        base_rgb
                    };
                    (col, stream.clamp(0.0, 1.0))
                }
                // 173: 百花争艳 — Audio-triggered blooming sparkles
                173 => {
                    if let Some(&(int, hue)) = self.sparkles.get(&kp.key_id) {
                        let col = if params.random_color {
                            hsv_to_rgb(hue, 0.95, 1.0)
                        } else {
                            base_rgb
                        };
                        (col, int.clamp(0.0, 1.0))
                    } else {
                        ([0, 0, 0], 0.0)
                    }
                }
                // 174: 正弦 — Oscillating horizontal sine curve matching audio energy
                174 => {
                    let active_amp = if energy > threshold {
                        energy * 0.48
                    } else {
                        0.08
                    };
                    let y_curve = 0.5
                        + active_amp * (kp.x_norm * std::f32::consts::TAU + self.phase * 3.0).sin();
                    let dist = (kp.y_norm - y_curve).abs();
                    let lvl = (1.0 - dist * 4.0).clamp(0.0, 1.0);
                    let col = if params.random_color {
                        hsv_to_rgb((kp.x_norm * 300.0 + self.phase * 40.0) % 360.0, 0.95, 1.0)
                    } else {
                        base_rgb
                    };
                    (col, lvl)
                }
                // 175: 彩色链条 — Chasing colored chain links along rows & columns
                175 => {
                    let linear_idx = (kp.row * cfg.num_cols + kp.col) as f32
                        / (cfg.all_keys.len().max(1) as f32);
                    let chain = ((linear_idx * 4.0 - self.phase * 0.9).fract() * 2.0 - 1.0).abs();
                    let lvl = (1.0 - chain * 1.4).clamp(0.0, 1.0) * (0.25 + 0.75 * energy);
                    let col = if params.random_color {
                        hsv_to_rgb((linear_idx * 360.0 + self.phase * 35.0) % 360.0, 0.95, 1.0)
                    } else {
                        base_rgb
                    };
                    (col, lvl)
                }
                // 176: 水花 — Expanding concentric splash rings on audio beats
                176 => {
                    let half_w = (params.splash_width_percent as f32 / 100.0) * 0.22;
                    let mut best = 0.0f32;
                    let mut best_hue = 200.0f32;
                    for &(r, hue) in &self.ripples {
                        let ring = 1.0 - ((radial - r).abs() / half_w.max(0.08));
                        if ring > best {
                            best = ring;
                            best_hue = hue;
                        }
                    }
                    let col = if params.random_color {
                        hsv_to_rgb(best_hue, 0.95, 1.0)
                    } else {
                        base_rgb
                    };
                    (col, best.clamp(0.0, 1.0))
                }
                // 177: 脉冲频谱 — Symmetric pulse bars driven by selected RhythmMode (0/1/2)
                177 => {
                    let spread = (energy * 0.8 + col_level * 0.4).clamp(0.0, 1.0);
                    let center_x = (kp.x_norm - 0.5).abs() * 2.0;
                    let lvl = ((spread - center_x * 0.7) * 2.0).clamp(0.0, 1.0);
                    let col = if params.random_color {
                        hsv_to_rgb(
                            (270.0 + center_x * 90.0 + self.phase * 30.0) % 360.0,
                            0.95,
                            1.0,
                        )
                    } else {
                        base_rgb
                    };
                    (col, lvl)
                }
                // 428: 动态频谱 — Multi-palette 21-preset spectrum bars
                428 => {
                    let bar =
                        ((col_level * (rows_f + 0.5)) - row_from_bottom * rows_f).clamp(0.0, 1.0);
                    let col = if params.color_typ == 21 || !params.random_color {
                        base_rgb
                    } else {
                        dynamic_palette_color(params.color_typ, kp.x_norm, kp.y_norm, self.phase)
                    };
                    (col, bar)
                }
                // Any other supported ID falls back cleanly to EQ bars
                _ => (base_rgb, col_level),
            };

            let final_rgb = apply_brightness_and_gamma(
                raw_rgb,
                intensity,
                params.brightness_percent,
                params.gamma,
            );
            frame.push((kp.key_id, final_rgb));
        }

        frame
    }

    /// Render optional side lightbar LEDs (`Tape_Count` > 0, mode `500..=503`).
    pub fn render_lightbar(
        &self,
        tape_count: usize,
        mode: i32,
        params: &ModeParams,
        audio: &AudioSnapshot,
    ) -> Vec<(u8, [u8; 3])> {
        if tape_count == 0 || mode <= 500 {
            return Vec::new();
        }
        let energy = audio.rhythm_energy(params.rhythm_mode);
        let bands = audio.slice_bands(1, 200, tape_count.max(1));
        let base_rgb = parse_hex_rgb(&params.color);

        (0..tape_count)
            .map(|idx| {
                let x = idx as f32 / tape_count.max(1) as f32;
                let lvl = match mode {
                    501 => bands.get(idx).copied().unwrap_or(energy),
                    502 => energy,
                    _ => {
                        (0.3 + 0.7 * energy)
                            * (0.5 + 0.5 * (x * std::f32::consts::TAU + self.phase * 2.0).sin())
                    }
                };
                let col = if params.random_color {
                    hsv_to_rgb((x * 360.0 + self.phase * 30.0) % 360.0, 0.95, 1.0)
                } else {
                    base_rgb
                };
                (
                    idx as u8,
                    apply_brightness_and_gamma(col, lvl, params.brightness_percent, params.gamma),
                )
            })
            .collect()
    }
}

fn apply_brightness_and_gamma(
    rgb: [u8; 3],
    intensity: f32,
    brightness_percent: u8,
    gamma: f64,
) -> [u8; 3] {
    let br = (brightness_percent as f32 / 100.0).clamp(0.0, 1.0);
    let i = (intensity * br).clamp(0.0, 1.0);
    if i <= 0.005 {
        return [0, 0, 0];
    }
    let scale = if gamma > 0.05 {
        i.powf(gamma as f32)
    } else {
        i
    };
    [
        (rgb[0] as f32 * scale).round().clamp(0.0, 255.0) as u8,
        (rgb[1] as f32 * scale).round().clamp(0.0, 255.0) as u8,
        (rgb[2] as f32 * scale).round().clamp(0.0, 255.0) as u8,
    ]
}

fn dynamic_palette_color(color_typ: i32, x: f32, y: f32, phase: f32) -> [u8; 3] {
    let base_hue = match color_typ {
        1 => (x * 300.0 + phase * 25.0) % 360.0,
        2 => (y * 160.0 + phase * 15.0) % 360.0,
        3 => (x * 120.0 + 180.0) % 360.0, // Cyan-Blue-Purple
        4 => (x * 90.0) % 360.0,          // Red-Orange-Yellow-Green
        5 => 180.0 + y * 90.0,            // Deep Ocean
        6 => 300.0 + x * 60.0,            // Magenta-Red
        _ => ((color_typ as f32 * 43.0) + x * 180.0 + phase * 20.0) % 360.0,
    };
    hsv_to_rgb(base_hue, 0.95, 1.0)
}

fn hsv_to_rgb(h_deg: f32, s: f32, v: f32) -> [u8; 3] {
    let h = h_deg.rem_euclid(360.0) / 60.0;
    let c = v * s;
    let x = c * (1.0 - (h % 2.0 - 1.0).abs());
    let m = v - c;
    let (r1, g1, b1) = if h < 1.0 {
        (c, x, 0.0)
    } else if h < 2.0 {
        (x, c, 0.0)
    } else if h < 3.0 {
        (0.0, c, x)
    } else if h < 4.0 {
        (0.0, x, c)
    } else if h < 5.0 {
        (x, 0.0, c)
    } else {
        (c, 0.0, x)
    };
    [
        ((r1 + m) * 255.0).round().clamp(0.0, 255.0) as u8,
        ((g1 + m) * 255.0).round().clamp(0.0, 255.0) as u8,
        ((b1 + m) * 255.0).round().clamp(0.0, 255.0) as u8,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_matches_expected_controls_and_constraints() {
        let store = EffectParamStore::default();
        let s168 = store.build_params_schema(168);
        assert_eq!(s168["SchemaVersion"], 1);
        assert_eq!(s168["Name"], "音频轻舞");
        assert_eq!(s168["SetCommand"], "ChangeEffectParams");
        assert_eq!(s168["Constraints"].as_array().unwrap().len(), 1);
        let keys_168: Vec<&str> = s168["Controls"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c["Key"].as_str())
            .collect();
        assert!(keys_168.contains(&"SampleMinimum"));
        assert!(keys_168.contains(&"SampleMaximum"));

        let s428 = store.build_params_schema(428);
        assert_eq!(s428["Name"], "动态频谱");
        assert!(s428["Values"].get("ColorTyp").is_some());

        let s180 = store.build_params_schema(180);
        assert_eq!(s180["Controls"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn renderer_produces_lit_keys_with_audio_and_empty_when_off() {
        let cfg = DeviceIniConfig::default_75_percent("010203040506");
        let params = ModeParams::default_for_mode(168);
        let mut audio = AudioSnapshot::default();
        audio.bins_256.fill(0.9);
        audio.rhythm_peak = 0.9;
        audio.rhythm_avg = 0.9;

        let mut renderer = EffectRendererState::new();
        let active = renderer.render_keyboard(&cfg, 168, &params, &audio, 0.03);
        assert!(active.iter().any(|(_, rgb)| *rgb != [0, 0, 0]));

        let off = renderer.render_keyboard(&cfg, 180, &params, &audio, 0.03);
        assert!(off.is_empty());
    }
}
