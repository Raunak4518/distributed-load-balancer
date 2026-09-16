use std::fmt::Display;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct ResultsWriter {
    rows: Mutex<Vec<(String, String, String)>>,
}

impl ResultsWriter {
    pub fn new() -> Self {
        ResultsWriter {
            rows: Mutex::new(Vec::new()),
        }
    }

    pub fn record(&self, scenario: &str, metric: &str, value: impl Display) {
        self.rows.lock().unwrap().push((
            scenario.to_string(),
            metric.to_string(),
            value.to_string(),
        ));
    }

    pub fn finish(&self, mode: &str, params: &[(&str, String)]) -> std::io::Result<PathBuf> {
        let dir = new_results_dir()?;
        write_metadata(&dir, mode, params)?;
        write_results_csv(&dir, &self.rows.lock().unwrap())?;
        Ok(dir)
    }
}

fn timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = secs / 86_400;
    let time_of_day = secs % 86_400;
    let (h, m, s) = (
        time_of_day / 3600,
        (time_of_day % 3600) / 60,
        time_of_day % 60,
    );
    let (y, mo, d) = civil_from_days(days as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}-{m:02}-{s:02}Z")
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn new_results_dir() -> std::io::Result<PathBuf> {
    let dir = PathBuf::from("results").join(timestamp());
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

fn git_sha() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn rustc_version() -> String {
    std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn write_metadata(dir: &Path, mode: &str, params: &[(&str, String)]) -> std::io::Result<()> {
    let logical_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);
    let mut json = String::new();
    json.push_str("{\n");
    json.push_str(&format!("  \"mode\": \"{}\",\n", json_escape(mode)));
    json.push_str(&format!(
        "  \"git_sha\": \"{}\",\n",
        json_escape(&git_sha())
    ));
    json.push_str(&format!(
        "  \"rustc_version\": \"{}\",\n",
        json_escape(&rustc_version())
    ));
    json.push_str(&format!("  \"os\": \"{}\",\n", std::env::consts::OS));
    json.push_str(&format!("  \"logical_cores\": {logical_cores},\n"));
    json.push_str("  \"params\": {\n");
    for (i, (k, v)) in params.iter().enumerate() {
        let comma = if i + 1 < params.len() { "," } else { "" };
        json.push_str(&format!(
            "    \"{}\": \"{}\"{comma}\n",
            json_escape(k),
            json_escape(v)
        ));
    }
    json.push_str("  }\n");
    json.push_str("}\n");
    std::fs::write(dir.join("metadata.json"), json)
}

fn write_results_csv(dir: &Path, rows: &[(String, String, String)]) -> std::io::Result<()> {
    let mut file = std::fs::File::create(dir.join("results.csv"))?;
    writeln!(file, "scenario,metric,value")?;
    for (scenario, metric, value) in rows {
        writeln!(
            file,
            "{},{},{}",
            csv_field(scenario),
            csv_field(metric),
            csv_field(value)
        )?;
    }
    Ok(())
}

fn csv_field(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}
