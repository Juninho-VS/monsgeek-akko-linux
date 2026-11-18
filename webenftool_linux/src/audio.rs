//! PipeWire / PulseAudio `.monitor` loopback capture and 256-bin FFT spectrum analyzer.
//!
//! Uses `libpulse-binding` + `libpulse-simple-binding` (pipewire-pulse compatible)
//! and `spectrum-analyzer` to compute normalized 256-bin frequency magnitudes plus
//! `rhythm_peak`, `rhythm_pulse`, `rhythm_avg`, and `rms_db` metrics.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use libpulse_binding::callbacks::ListResult;
use libpulse_binding::context::{Context, FlagSet, State as ContextState};
use libpulse_binding::def::BufferAttr;
use libpulse_binding::mainloop::standard::{IterateResult, Mainloop};
use libpulse_binding::operation::{Operation, State as OpState};
use libpulse_binding::sample::{Format, Spec};
use libpulse_binding::stream::Direction;
use libpulse_simple_binding::Simple;
use spectrum_analyzer::scaling::divide_by_N_sqrt;
use spectrum_analyzer::windows::hann_window;
use spectrum_analyzer::{FrequencyLimit, samples_fft_to_spectrum};

pub const SAMPLE_RATE: u32 = 44100;
pub const FFT_SIZE: usize = 2048;
pub const NUM_BINS: usize = 256;

const APP_NAME: &str = "webenftool-linux";
const STREAM_NAME: &str = "audio-reactive-monitor";

/// Snapshot of the current audio spectrum and beat/rhythm envelopes.
#[derive(Debug, Clone)]
pub struct AudioSnapshot {
    /// Normalized `[0.0, 1.0]` magnitudes across 256 frequency bins (`20 Hz .. 11 kHz`).
    pub bins_256: [f32; NUM_BINS],
    /// Relative dB/level score `[0..=100]`.
    pub rms_db: i32,
    /// Fast-attack peak envelope (`RhythmMode = 0`).
    pub rhythm_peak: f32,
    /// Transient / beat-onset pulse (`RhythmMode = 1`).
    pub rhythm_pulse: f32,
    /// Smoothed average energy (`RhythmMode = 2`).
    pub rhythm_avg: f32,
}

impl Default for AudioSnapshot {
    fn default() -> Self {
        Self {
            bins_256: [0.0; NUM_BINS],
            rms_db: 0,
            rhythm_peak: 0.0,
            rhythm_pulse: 0.0,
            rhythm_avg: 0.0,
        }
    }
}

impl AudioSnapshot {
    /// Return band energies over `[sample_min..=sample_max]` grouped into `band_count` buckets.
    pub fn slice_bands(&self, sample_min: i32, sample_max: i32, band_count: usize) -> Vec<f32> {
        let count = band_count.max(1);
        let lo = sample_min.clamp(0, (NUM_BINS - 2) as i32) as usize;
        let hi = sample_max.clamp((lo + 1) as i32, (NUM_BINS - 1) as i32) as usize;
        let span = hi - lo + 1;

        let mut bands = vec![0.0f32; count];
        for (i, out) in bands.iter_mut().enumerate() {
            let start = lo + (i * span) / count;
            let end = (lo + ((i + 1) * span) / count).max(start + 1).min(hi + 1);
            let mut sum = 0.0f32;
            let mut n = 0usize;
            for &v in &self.bins_256[start..end] {
                sum += v;
                n += 1;
            }
            *out = if n > 0 { sum / n as f32 } else { 0.0 };
        }
        bands
    }

    /// Return the scalar energy corresponding to `RhythmMode` (`0=Peak, 1=Pulse, 2=Mean`).
    pub fn rhythm_energy(&self, rhythm_mode: i32) -> f32 {
        match rhythm_mode {
            0 => self.rhythm_peak,
            1 => self.rhythm_pulse,
            _ => self.rhythm_avg,
        }
    }
}

/// Discovered PulseAudio / PipeWire capture source metadata.
#[derive(Debug, Clone)]
pub struct SourceEntry {
    pub name: String,
    pub description: String,
    pub is_monitor: bool,
}

fn with_pulse_context<T>(
    action: impl FnOnce(&mut Mainloop, &Context) -> Result<T, String>,
) -> Result<T, String> {
    let mut mainloop = Mainloop::new().ok_or("Failed to create PulseAudio mainloop")?;
    let mut context =
        Context::new(&mainloop, APP_NAME).ok_or("Failed to create PulseAudio context")?;
    context
        .connect(None, FlagSet::NOFLAGS, None)
        .map_err(|e| format!("PulseAudio connect failed: {e}"))?;

    loop {
        match mainloop.iterate(true) {
            IterateResult::Success(_) => {}
            IterateResult::Quit(_) => return Err("PulseAudio mainloop quit".into()),
            IterateResult::Err(e) => return Err(format!("PulseAudio mainloop error: {e}")),
        }
        match context.get_state() {
            ContextState::Ready => break,
            ContextState::Failed => return Err("PulseAudio context failed".into()),
            ContextState::Terminated => return Err("PulseAudio context terminated".into()),
            _ => {}
        }
    }

    let result = action(&mut mainloop, &context);
    context.disconnect();
    result
}

fn wait_for_op<T: ?Sized>(mainloop: &mut Mainloop, op: &Operation<T>) -> Result<(), String> {
    loop {
        match mainloop.iterate(true) {
            IterateResult::Success(_) => {}
            IterateResult::Quit(_) => return Err("PulseAudio mainloop quit".into()),
            IterateResult::Err(e) => return Err(format!("PulseAudio mainloop error: {e}")),
        }
        match op.get_state() {
            OpState::Done => return Ok(()),
            OpState::Cancelled => return Err("PulseAudio operation cancelled".into()),
            OpState::Running => {}
        }
    }
}

/// List available PulseAudio/PipeWire capture sources (monitors + inputs).
pub fn list_sources() -> Result<Vec<SourceEntry>, String> {
    with_pulse_context(|mainloop, context| {
        let sources = Rc::new(RefCell::new(Vec::new()));
        let collect = sources.clone();
        let op = context.introspect().get_source_info_list(move |res| {
            if let ListResult::Item(info) = res {
                collect.borrow_mut().push(SourceEntry {
                    name: info.name.as_deref().unwrap_or_default().to_string(),
                    description: info.description.as_deref().unwrap_or_default().to_string(),
                    is_monitor: info.monitor_of_sink.is_some(),
                });
            }
        });
        wait_for_op(mainloop, &op)?;
        let out = sources.borrow().clone();
        Ok(out)
    })
}

fn default_monitor_name() -> Option<String> {
    with_pulse_context(|mainloop, context| {
        let name = Rc::new(RefCell::new(None));
        let collect = name.clone();
        let op = context.introspect().get_server_info(move |info| {
            *collect.borrow_mut() = info.default_sink_name.as_deref().map(str::to_string);
        });
        wait_for_op(mainloop, &op)?;
        let resolved = name.borrow().clone();
        Ok(resolved)
    })
    .ok()
    .flatten()
    .map(|sink| format!("{sink}.monitor"))
}

/// Resolve the preferred monitor source (`<default_sink>.monitor` if present, else first monitor).
pub fn resolve_source(requested: Option<&str>) -> Result<SourceEntry, String> {
    let sources = list_sources()?;
    if sources.is_empty() {
        return Err("No PulseAudio/PipeWire capture sources found".into());
    }
    let Some(req) = requested else {
        if let Some(def) = default_monitor_name()
            && let Some(found) = sources.iter().find(|s| s.name == def)
        {
            return Ok(found.clone());
        }
        if let Some(found) = sources.iter().find(|s| s.is_monitor) {
            return Ok(found.clone());
        }
        return Ok(sources.into_iter().next().unwrap());
    };

    if let Some(exact) = sources
        .iter()
        .find(|s| s.name == req || s.description == req)
    {
        return Ok(exact.clone());
    }
    let req_lower = req.to_ascii_lowercase();
    let matches: Vec<&SourceEntry> = sources
        .iter()
        .filter(|s| {
            s.name.to_ascii_lowercase().contains(&req_lower)
                || s.description.to_ascii_lowercase().contains(&req_lower)
        })
        .collect();
    match matches.as_slice() {
        [one] => Ok((*one).clone()),
        [] => Err(format!("No audio source matches '{req}'")),
        many => Err(format!(
            "Audio source '{req}' is ambiguous ({} matches)",
            many.len()
        )),
    }
}

fn open_record_stream(source_name: &str) -> Result<Simple, String> {
    let spec = Spec {
        format: Format::F32le,
        channels: 1,
        rate: SAMPLE_RATE,
    };
    if !spec.is_valid() {
        return Err("Invalid PulseAudio sample spec".into());
    }
    let frag = (SAMPLE_RATE / 100) * 4; // ~10ms mono f32
    let attr = BufferAttr {
        maxlength: frag * 4,
        tlength: u32::MAX,
        prebuf: u32::MAX,
        minreq: u32::MAX,
        fragsize: frag,
    };
    Simple::new(
        None,
        APP_NAME,
        Direction::Record,
        Some(source_name),
        STREAM_NAME,
        &spec,
        None,
        Some(&attr),
    )
    .map_err(|e| format!("Failed to open PulseAudio source '{source_name}': {e}"))
}

/// Rolling AGC and rhythm tracker state across frames.
#[derive(Debug, Default)]
pub struct AnalyzerState {
    peak_ref: f32,
    prev_avg: f32,
    smooth_peak: f32,
    smooth_pulse: f32,
    smooth_avg: f32,
}

impl AnalyzerState {
    /// Compute normalized 256-bin FFT spectrum and rhythm envelopes from `samples` (`len >= FFT_SIZE`).
    pub fn analyze(&mut self, samples: &[f32], sample_rate: u32) -> AudioSnapshot {
        if samples.len() < FFT_SIZE {
            return AudioSnapshot::default();
        }
        let slice = &samples[samples.len() - FFT_SIZE..];
        let mut sum_sq = 0.0f32;
        let mut peak_amp = 0.0f32;
        for &s in slice {
            sum_sq += s * s;
            peak_amp = peak_amp.max(s.abs());
        }
        let rms = (sum_sq / slice.len() as f32).sqrt();
        if peak_amp < 0.0005 {
            self.peak_ref *= 0.995;
            self.smooth_peak *= 0.85;
            self.smooth_pulse *= 0.78;
            self.smooth_avg *= 0.88;
            self.prev_avg = self.smooth_avg;
            return AudioSnapshot {
                bins_256: [0.0; NUM_BINS],
                rms_db: 0,
                rhythm_peak: self.smooth_peak,
                rhythm_pulse: self.smooth_pulse,
                rhythm_avg: self.smooth_avg,
            };
        }

        let windowed = hann_window(slice);
        let spectrum = match samples_fft_to_spectrum(
            &windowed,
            sample_rate,
            FrequencyLimit::Range(20.0, 11025.0),
            Some(&divide_by_N_sqrt),
        ) {
            Ok(s) => s,
            Err(_) => return AudioSnapshot::default(),
        };

        let mut raw_bins = [0.0f32; NUM_BINS];
        let mut counts = [0u16; NUM_BINS];
        // Logarithmic-ish mapping from 20 Hz .. 11025 Hz onto 256 bins so bass/mids get crisp detail.
        let min_f = 20.0f32.ln();
        let max_f = 11025.0f32.ln();
        let inv_span = (NUM_BINS - 1) as f32 / (max_f - min_f);
        for (freq, mag) in spectrum.data().iter() {
            let f = freq.val().clamp(20.0, 11025.0);
            let bin = (((f.ln() - min_f) * inv_span).round() as usize).min(NUM_BINS - 1);
            raw_bins[bin] += mag.val();
            counts[bin] = counts[bin].saturating_add(1);
        }
        // Linearly fill sparse low-frequency log gaps and compute raw peak
        let mut last_nonzero = 0usize;
        for b in 0..NUM_BINS {
            if counts[b] > 0 {
                raw_bins[b] /= counts[b] as f32;
                last_nonzero = b;
            } else if last_nonzero < b {
                raw_bins[b] = raw_bins[last_nonzero] * 0.85;
            }
        }

        let frame_peak_bin = raw_bins.iter().copied().fold(0.0f32, f32::max);
        self.peak_ref = frame_peak_bin.max(self.peak_ref * 0.992).max(1e-4);

        let mut bins_256 = [0.0f32; NUM_BINS];
        let mut total_norm = 0.0f32;
        for (dst, &raw) in bins_256.iter_mut().zip(raw_bins.iter()) {
            let norm = (raw / self.peak_ref).clamp(0.0, 1.0).powf(0.65);
            *dst = norm;
            total_norm += norm;
        }
        let mean_energy = (total_norm / NUM_BINS as f32).clamp(0.0, 1.0);
        let peak_energy = bins_256.iter().copied().fold(0.0f32, f32::max);
        let flux = (mean_energy - self.prev_avg).max(0.0) * 4.5;
        self.prev_avg = mean_energy;

        self.smooth_peak = peak_energy.max(self.smooth_peak * 0.86).clamp(0.0, 1.0);
        self.smooth_pulse = flux.max(self.smooth_pulse * 0.78).clamp(0.0, 1.0);
        self.smooth_avg = (self.smooth_avg * 0.55 + mean_energy * 0.45).clamp(0.0, 1.0);

        // Convert RMS into 0..100 scale (`Db`)
        let db = 20.0 * (rms.max(1e-5)).log10(); // -100 .. 0 dBFS
        let rms_db = ((db + 70.0) * (100.0 / 65.0)).clamp(0.0, 100.0).round() as i32;

        AudioSnapshot {
            bins_256,
            rms_db,
            rhythm_peak: self.smooth_peak,
            rhythm_pulse: self.smooth_pulse,
            rhythm_avg: self.smooth_avg,
        }
    }
}

/// Manages background audio capture (or optional synthetic test audio).
pub struct AudioEngine {
    pub source_name: String,
    pub available: bool,
    latest: Arc<Mutex<AudioSnapshot>>,
    running: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl AudioEngine {
    /// Start PipeWire/PulseAudio loopback capture, falling back cleanly if `synthetic` is true
    /// or no audio server is reachable in headless CI.
    pub fn start(requested_source: Option<&str>, synthetic: bool) -> Self {
        let latest = Arc::new(Mutex::new(AudioSnapshot::default()));
        let running = Arc::new(AtomicBool::new(true));

        if synthetic {
            let latest_bg = Arc::clone(&latest);
            let run_bg = Arc::clone(&running);
            let handle = thread::spawn(move || {
                let mut state = AnalyzerState::default();
                let mut phase = 0.0f32;
                let mut samples = vec![0.0f32; FFT_SIZE];
                while run_bg.load(Ordering::Relaxed) {
                    let bass_freq = 90.0 + 70.0 * (phase * 0.7).sin();
                    let mid_freq = 440.0 + 180.0 * (phase * 1.3).cos();
                    let beat = (0.5 + 0.5 * (phase * 4.0).sin()).powf(2.0);
                    for (i, s) in samples.iter_mut().enumerate() {
                        let t = i as f32 / SAMPLE_RATE as f32 + phase;
                        *s = (0.45 * beat * (2.0 * std::f32::consts::PI * bass_freq * t).sin())
                            + (0.25 * (2.0 * std::f32::consts::PI * mid_freq * t).sin());
                    }
                    let snap = state.analyze(&samples, SAMPLE_RATE);
                    if let Ok(mut guard) = latest_bg.lock() {
                        *guard = snap;
                    }
                    phase += 0.03;
                    thread::sleep(Duration::from_millis(25));
                }
            });
            return Self {
                source_name: "<synthetic-audio>".to_string(),
                available: true,
                latest,
                running,
                worker: Some(handle),
            };
        }

        let resolved = match resolve_source(requested_source) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "PulseAudio source unavailable; audio input inactive");
                return Self {
                    source_name: "<unavailable>".to_string(),
                    available: false,
                    latest,
                    running,
                    worker: None,
                };
            }
        };

        let simple = match open_record_stream(&resolved.name) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(source = %resolved.name, error = %e, "Failed to open PulseAudio record stream");
                return Self {
                    source_name: resolved.name,
                    available: false,
                    latest,
                    running,
                    worker: None,
                };
            }
        };

        let latest_bg = Arc::clone(&latest);
        let run_bg = Arc::clone(&running);
        let src_label = resolved.name.clone();
        tracing::info!(source = %src_label, monitor = resolved.is_monitor, "Started PipeWire/PulseAudio loopback capture");

        let handle = thread::spawn(move || {
            const CHUNK_SAMPLES: usize = 512;
            let mut raw_bytes = vec![0u8; CHUNK_SAMPLES * 4];
            let mut ring = vec![0.0f32; FFT_SIZE];
            let mut analyzer = AnalyzerState::default();

            while run_bg.load(Ordering::Relaxed) {
                if simple.read(&mut raw_bytes).is_err() {
                    thread::sleep(Duration::from_millis(20));
                    continue;
                }
                ring.copy_within(CHUNK_SAMPLES.., 0);
                let tail = &mut ring[FFT_SIZE - CHUNK_SAMPLES..];
                let (chunks, _) = raw_bytes.as_chunks::<4>();
                for (dst, &chunk) in tail.iter_mut().zip(chunks) {
                    *dst = f32::from_le_bytes(chunk);
                }
                let snap = analyzer.analyze(&ring, SAMPLE_RATE);
                if let Ok(mut guard) = latest_bg.lock() {
                    *guard = snap;
                }
            }
        });

        Self {
            source_name: src_label,
            available: true,
            latest,
            running,
            worker: Some(handle),
        }
    }

    pub fn snapshot(&self) -> AudioSnapshot {
        self.latest.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

impl Drop for AudioEngine {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(h) = self.worker.take() {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fft_analyzes_sine_and_silence() {
        let mut analyzer = AnalyzerState::default();
        let silence = vec![0.0f32; FFT_SIZE];
        let s_snap = analyzer.analyze(&silence, SAMPLE_RATE);
        assert_eq!(s_snap.rms_db, 0);

        let mut sine = vec![0.0f32; FFT_SIZE];
        for (i, v) in sine.iter_mut().enumerate() {
            let t = i as f32 / SAMPLE_RATE as f32;
            *v = 0.5 * (2.0 * std::f32::consts::PI * 220.0 * t).sin();
        }
        let a_snap = analyzer.analyze(&sine, SAMPLE_RATE);
        assert!(a_snap.rms_db > 40);
        assert!(a_snap.rhythm_peak > 0.5);
        assert!(a_snap.rhythm_pulse > 0.0);
        let bands = a_snap.slice_bands(1, 254, 16);
        assert_eq!(bands.len(), 16);
        assert!(bands.iter().any(|&b| b > 0.2));
    }
}
