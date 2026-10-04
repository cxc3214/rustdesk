//! SimpleDesk audit: upload finished incoming-session recordings to the
//! central audit server, then remove the local copy. One background thread
//! inside the service process -- no external scripts or scheduled tasks.
//!
//! Upload endpoints are tried in priority order:
//!   1. Entries the user set via option "simpledesk-upload-url" (comma
//!      separated), in the given order -- manual entries add and reorder.
//!   2. Built-in defaults (LAN 99 first, public domain) appended as
//!      fallback when not already listed. Defaults are never dropped.
//!
//! Session metadata: connection.rs drops a JSON sidecar per authed incoming
//! session (peer id/name/ip + timestamps) into <video dir>/meta/. The
//! uploader matches each video file to its session by timestamp and sends
//! the meta along as the multipart "meta" field.

use hbb_common::log;
use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
    thread,
    time::{Duration, SystemTime},
};

const LAN_UPLOAD_URL: &str = "http://192.168.10.99:18090/api/upload";
const WAN_UPLOAD_URL: &str = "https://desk.simplesoft.cn/audit-api/upload";
// Token is injected at build time via the SIMPLEDESK_AUDIT_TOKEN env var
// (CI repository secret). Never commit the real value to the repo.
const AUTH_TOKEN: &str = match option_env!("SIMPLEDESK_AUDIT_TOKEN") {
    Some(t) => t,
    None => "BUILD_TIME_PLACEHOLDER",
};
const SCAN_INTERVAL: Duration = Duration::from_secs(60);
const STABLE_AGE: Duration = Duration::from_secs(30);
const META_KEEP: Duration = Duration::from_secs(7 * 24 * 3600);

/// True when automatic recording of incoming sessions is switched on, i.e.
/// a video file (and thus a meta sidecar) will exist for this session.
pub fn record_meta_enabled() -> bool {
    let opt = hbb_common::config::Config::get_option("allow-auto-record-incoming");
    if opt.is_empty() {
        false
    } else {
        hbb_common::config::option2bool("allow-auto-record-incoming", &opt)
    }
}

fn video_dir() -> PathBuf {
    #[cfg(windows)]
    let root = crate::platform::is_root();
    #[cfg(not(windows))]
    let root = false;
    PathBuf::from(crate::ui_interface::video_save_directory(root))
}

fn meta_dir() -> PathBuf {
    video_dir().join("meta")
}

/// Called by connection.rs right after an incoming session is authenticated.
/// Returns the sidecar path so the connection can finalize it on close.
pub fn write_session_meta(peer_id: &str, peer_name: &str, peer_ip: &str, uniq: i32) -> Option<PathBuf> {
    let dir = meta_dir();
    if dir.as_os_str().is_empty() || fs::create_dir_all(&dir).is_err() {
        return None;
    }
    let now = chrono::Local::now();
    let epoch = now.timestamp();
    let host_id = hbb_common::config::Config::get_id();
    let file = dir.join(format!(
        "sess_{}_{}.json",
        now.format("%Y%m%d%H%M%S"),
        uniq
    ));
    let v = json!({
        "peer_id": peer_id,
        "peer_name": peer_name,
        "peer_ip": peer_ip,
        "host_id": host_id,
        "started_at": now.format("%Y-%m-%d %H:%M:%S").to_string(),
        "started_epoch": epoch,
    });
    match fs::write(&file, v.to_string()) {
        Ok(_) => Some(file),
        Err(e) => {
            log::warn!("audit meta write failed: {}", e);
            None
        }
    }
}

/// Called by connection.rs when the session closes: stamps end time and
/// duration into the sidecar.
pub fn finalize_session_meta(path: &Path) {
    let Ok(raw) = fs::read_to_string(path) else { return };
    let Ok(mut v) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return;
    };
    let now = chrono::Local::now();
    v["ended_at"] = json!(now.format("%Y-%m-%d %H:%M:%S").to_string());
    if let Some(start) = v["started_epoch"].as_i64() {
        v["duration_s"] = json!(std::cmp::max(0, now.timestamp() - start));
    }
    allow_err_write(path, v.to_string());
}

fn allow_err_write(path: &Path, content: String) {
    if let Err(e) = fs::write(path, content) {
        log::warn!("audit meta finalize failed: {}", e);
    }
}

/// Ordered upload endpoints. Entries from the manual option
/// (comma separated) come first in their given order; any built-in default
/// (LAN 99, WAN domain) that is not already listed is appended as fallback,
/// so the defaults are never lost -- manual input only adds and reorders.
fn upload_urls() -> Vec<String> {
    let mut urls: Vec<String> = Vec::new();
    let custom = hbb_common::config::Config::get_option("simpledesk-upload-url");
    for s in custom.trim().split([',', ';', ' ', '\n']) {
        let s = s.trim();
        if !s.is_empty() && !urls.iter().any(|u| u == s) {
            urls.push(s.to_string());
        }
    }
    for d in [LAN_UPLOAD_URL, WAN_UPLOAD_URL] {
        if !urls.iter().any(|u| u == d) {
            urls.push(d.to_string());
        }
    }
    urls
}

pub fn start() {
    thread::spawn(|| {
        log::info!("audit upload thread started, targets {:?}", upload_urls());
        loop {
            if let Err(e) = scan_once() {
                log::warn!("audit upload scan failed: {}", e);
            }
            thread::sleep(SCAN_INTERVAL);
        }
    });
}

/// Parse the millisecond timestamp out of a recording filename
/// (incoming_<id>_<yyyymmddHHMMSSfff>_...) into seconds since epoch.
fn video_ts_epoch(name: &str) -> Option<i64> {
    let ts = name.split('_').nth(2)?;
    let naive = chrono::NaiveDateTime::parse_from_str(ts, "%Y%m%d%H%M%S%3f").ok()?;
    Some(naive.and_local_timezone(chrono::Local).single()?.timestamp())
}

/// Find the session-meta sidecar whose start is the latest one not after
/// the video's creation (recorder starts right after session auth).
fn find_meta_for_video(video_name: &str) -> Option<(PathBuf, String)> {
    let vts = video_ts_epoch(video_name)?;
    let dir = meta_dir();
    let mut best: Option<(i64, PathBuf, String)> = None;
    for entry in fs::read_dir(&dir).ok()? {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        if path.extension().map(|e| e == "json") != Some(true) {
            continue;
        }
        let Ok(raw) = fs::read_to_string(&path) else { continue };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) else {
            continue;
        };
        let Some(start) = v["started_epoch"].as_i64() else { continue };
        // Recorder is created ~0.5-2s after auth; allow a small lead.
        if start <= vts + 2 && best.as_ref().map(|(b, _, _)| start > *b).unwrap_or(true) {
            best = Some((start, path, raw));
        }
    }
    best.map(|(_, p, raw)| (p, raw))
}

/// Remove sidecars older than META_KEEP (their video is long gone).
fn janitor_meta() {
    let Ok(entries) = fs::read_dir(meta_dir()) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        let old = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| SystemTime::now().duration_since(t).ok())
            .map(|age| age > META_KEEP)
            .unwrap_or(false);
        if old {
            fs::remove_file(&path).ok();
        }
    }
}

fn scan_once() -> std::io::Result<()> {
    let dir = video_dir();
    if dir.as_os_str().is_empty() || !dir.is_dir() {
        return Ok(());
    }
    janitor_meta();
    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(180))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            log::warn!("audit upload http client init failed: {}", e);
            return Ok(());
        }
    };
    let urls = upload_urls();
    for entry in fs::read_dir(&dir)? {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        // Only incoming-session recordings are audit evidence.
        if !name.starts_with("incoming_") {
            continue;
        }
        if !(name.ends_with(".webm") || name.ends_with(".mp4")) {
            continue;
        }
        // Skip files still being written (the webm grows during a session).
        let stable = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| SystemTime::now().duration_since(t).ok())
            .map(|age| age >= STABLE_AGE)
            .unwrap_or(false);
        if !stable {
            continue;
        }
        // Filename: incoming_<this-device-id>_<ts>_display_<n>_<codec>.webm
        let device_id = name.split('_').nth(1).unwrap_or("unknown").to_string();
        let meta = find_meta_for_video(&name);
        let meta_json = meta.as_ref().map(|(_, raw)| raw.clone());
        match upload_one(&client, &urls, &path, &name, &device_id, meta_json) {
            Ok(true) => {
                if fs::remove_file(&path).is_ok() {
                    log::info!("audit uploaded and removed {}", name);
                }
                if let Some((mp, _)) = meta {
                    fs::remove_file(mp).ok();
                }
            }
            Ok(false) => log::warn!("audit upload rejected by all endpoints, will retry {}", name),
            Err(e) => log::warn!("audit upload failed for {}: {}", name, e),
        }
    }
    Ok(())
}

/// Try each endpoint in priority order; the first 2xx wins. Network errors
/// fall through to the next endpoint. Returns Ok(false) when every endpoint
/// answered but rejected us, Err when every endpoint was unreachable.
fn upload_one(
    client: &reqwest::blocking::Client,
    urls: &[String],
    path: &Path,
    name: &str,
    device_id: &str,
    meta_json: Option<String>,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let mut last_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;
    let mut any_answered = false;
    for url in urls {
        let part = match reqwest::blocking::multipart::Part::file(path) {
            Ok(p) => p.file_name(name.to_string()),
            Err(e) => return Err(Box::new(e)),
        };
        let mut form = reqwest::blocking::multipart::Form::new()
            .text("peer_id", device_id.to_string())
            .part("file", part);
        if let Some(m) = &meta_json {
            form = form.text("meta", m.clone());
        }
        match client
            .post(url.as_str())
            .header("X-Auth-Token", AUTH_TOKEN)
            .multipart(form)
            .send()
        {
            Ok(resp) => {
                any_answered = true;
                if resp.status().is_success() {
                    log::info!("audit upload {} succeeded via {}", name, url);
                    return Ok(true);
                }
                log::warn!(
                    "audit upload {} rejected by {} (status {}), trying next",
                    name,
                    url,
                    resp.status()
                );
            }
            Err(e) => {
                log::warn!("audit upload {} unreachable via {}: {}", name, url, e);
                last_err = Some(Box::new(e));
            }
        }
    }
    if any_answered {
        Ok(false)
    } else {
        Err(last_err.unwrap_or_else(|| "no upload endpoint reachable".into()))
    }
}
