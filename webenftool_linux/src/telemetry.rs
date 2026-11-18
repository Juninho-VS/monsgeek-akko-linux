//! Native Linux system telemetry reader for `GetHardware` and HID `0x0B` sync packets.

use std::fs;
use std::path::Path;
use std::sync::Mutex;

use crate::hid_beiying::TelemetryPacketData;

#[derive(Debug, Default)]
struct CpuTimes {
    total: u64,
    idle: u64,
}

/// Stateful Linux `/proc` + `/sys` hardware telemetry collector.
pub struct TelemetryReader {
    prev_cpu: Mutex<CpuTimes>,
}

impl Default for TelemetryReader {
    fn default() -> Self {
        Self::new()
    }
}

impl TelemetryReader {
    pub fn new() -> Self {
        let initial = read_proc_stat().unwrap_or_default();
        Self {
            prev_cpu: Mutex::new(initial),
        }
    }

    /// Sample CPU load, memory usage, CPU temperature, and local civil time.
    pub fn sample(&self) -> TelemetryPacketData {
        let cpu_load = self.sample_cpu_load();
        let mem_usage = read_mem_usage_percent().unwrap_or(0);
        let cpu_temp = read_cpu_temp_celsius().unwrap_or(45);
        let (year, month, day, hour, minute, second, weekday) = read_local_time();

        TelemetryPacketData {
            volume: 50,
            cpu_load,
            mem_usage,
            year,
            month,
            day,
            hour,
            minute,
            second,
            weekday,
            cpu_temp,
            weather_code: 0,
            weather_temp: 0,
        }
    }

    fn sample_cpu_load(&self) -> u8 {
        let Some(cur) = read_proc_stat() else {
            return 0;
        };
        let Ok(mut prev) = self.prev_cpu.lock() else {
            return 0;
        };
        let dt_total = cur.total.saturating_sub(prev.total);
        let dt_idle = cur.idle.saturating_sub(prev.idle);
        *prev = cur;
        if dt_total == 0 {
            return 0;
        }
        let busy = dt_total.saturating_sub(dt_idle);
        ((busy * 100) / dt_total).min(100) as u8
    }
}

fn read_proc_stat() -> Option<CpuTimes> {
    let txt = fs::read_to_string("/proc/stat").ok()?;
    let line = txt.lines().next()?;
    let mut parts = line.split_whitespace();
    if parts.next()? != "cpu" {
        return None;
    }
    let vals: Vec<u64> = parts.filter_map(|p| p.parse::<u64>().ok()).collect();
    if vals.len() < 4 {
        return None;
    }
    let idle = vals[3].saturating_add(*vals.get(4).unwrap_or(&0));
    let total: u64 = vals.iter().sum();
    Some(CpuTimes { total, idle })
}

fn read_mem_usage_percent() -> Option<u8> {
    let txt = fs::read_to_string("/proc/meminfo").ok()?;
    let mut total_kb = 0u64;
    let mut avail_kb = 0u64;
    for line in txt.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            total_kb = rest.split_whitespace().next()?.parse().ok()?;
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            avail_kb = rest.split_whitespace().next()?.parse().ok()?;
        }
    }
    if total_kb == 0 {
        return None;
    }
    let used = total_kb.saturating_sub(avail_kb);
    Some(((used * 100) / total_kb).min(100) as u8)
}

fn read_cpu_temp_celsius() -> Option<u8> {
    let thermal = Path::new("/sys/class/thermal");
    if let Ok(entries) = fs::read_dir(thermal) {
        for entry in entries.flatten() {
            let p = entry.path().join("temp");
            if let Ok(raw) = fs::read_to_string(p)
                && let Ok(millideg) = raw.trim().parse::<i64>()
                && (1000..150_000).contains(&millideg)
            {
                return Some((millideg / 1000).clamp(0, 127) as u8);
            }
        }
    }
    None
}

fn read_local_time() -> (u16, u8, u8, u8, u8, u8, u8) {
    // SAFETY: Standard POSIX `time` + `localtime_r` on stack-allocated `libc::tm`.
    unsafe {
        let mut now: libc::time_t = 0;
        libc::time(&mut now);
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&now, &mut tm).is_null() {
            return (2026, 1, 1, 0, 0, 0, 1);
        }
        let year = (tm.tm_year + 1900).clamp(2000, 2100) as u16;
        let month = (tm.tm_mon + 1).clamp(1, 12) as u8;
        let day = tm.tm_mday.clamp(1, 31) as u8;
        let hour = tm.tm_hour.clamp(0, 23) as u8;
        let minute = tm.tm_min.clamp(0, 59) as u8;
        let second = tm.tm_sec.clamp(0, 59) as u8;
        let weekday = tm.tm_wday.clamp(0, 6) as u8;
        (year, month, day, hour, minute, second, weekday)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_telemetry_bounds() {
        let reader = TelemetryReader::new();
        let t = reader.sample();
        assert!(t.cpu_load <= 100);
        assert!(t.mem_usage <= 100);
        assert!((2000..=2100).contains(&t.year));
        assert!((1..=12).contains(&t.month));
        assert!((1..=31).contains(&t.day));
    }
}
