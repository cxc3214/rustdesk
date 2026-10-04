//! SimpleDesk audit: upload finished incoming-session recordings to the
//! central audit server, then remove the local copy. One background thread
//! inside the service process -- no external scripts or scheduled tasks.
//!
//! Upload endpoints are tried in priority order:
//!   1. Entries the user set via option "simpledesk-upload-url" (comma
//!      separated), in the given order -- manual entries add and reorder.
//!   2. Built-in defaults (LAN 99 first, public domain) appended as
//!      fallback when not already listed. Defaults are never dropped.

use hbb_common::log;
use std::{
    fs,
    path::PathBuf,
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

fn scan_once() -> std::io::Result<()> {
    #[cfg(windows)]
    let root = crate::platform::is_root();
    #[cfg(not(windows))]
    let root = false;
    let dir_str = crate::ui_interface::video_save_directory(root);
    if dir_str.is_empty() {
        return Ok(());
    }
    let dir = PathBuf::from(dir_str);
    if !dir.is_dir() {
        return Ok(());
    }
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
        match upload_one(&client, &urls, &path, &name, &device_id) {
            Ok(true) => {
                if fs::remove_file(&path).is_ok() {
                    log::info!("audit uploaded and removed {}", name);
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
    path: &std::path::Path,
    name: &str,
    device_id: &str,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let mut last_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;
    let mut any_answered = false;
    for url in urls {
        let part = match reqwest::blocking::multipart::Part::file(path) {
            Ok(p) => p.file_name(name.to_string()),
            Err(e) => return Err(Box::new(e)),
        };
        let form = reqwest::blocking::multipart::Form::new()
            .text("peer_id", device_id.to_string())
            .part("file", part);
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
