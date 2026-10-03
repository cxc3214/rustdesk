//! SimpleDesk audit: upload finished incoming-session recordings to the
//! central audit server, then remove the local copy. One background thread
//! inside the service process -- no external scripts or scheduled tasks.

use hbb_common::log;
use std::{
    fs,
    path::PathBuf,
    thread,
    time::{Duration, SystemTime},
};

const UPLOAD_URL: &str = "https://desk.simplesoft.cn/audit-api/upload";
const AUTH_TOKEN: &str = "6ada9fda217fe1203757501a71eb4fd3fa7a8a86db43b47466df4888ba518d0a";
const SCAN_INTERVAL: Duration = Duration::from_secs(60);
const STABLE_AGE: Duration = Duration::from_secs(30);

pub fn start() {
    thread::spawn(|| {
        log::info!("audit upload thread started, target {}", UPLOAD_URL);
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
        match upload_one(&client, &path, &name, &device_id) {
            Ok(true) => {
                if fs::remove_file(&path).is_ok() {
                    log::info!("audit uploaded and removed {}", name);
                }
            }
            Ok(false) => log::warn!("audit upload rejected by server, will retry {}", name),
            Err(e) => log::warn!("audit upload failed for {}: {}", name, e),
        }
    }
    Ok(())
}

fn upload_one(
    client: &reqwest::blocking::Client,
    path: &std::path::Path,
    name: &str,
    device_id: &str,
) -> Result<bool, reqwest::Error> {
    let part = reqwest::blocking::multipart::Part::file(path)?.file_name(name.to_string());
    let form = reqwest::blocking::multipart::Form::new()
        .text("peer_id", device_id.to_string())
        .part("file", part);
    let resp = client
        .post(UPLOAD_URL)
        .header("X-Auth-Token", AUTH_TOKEN)
        .multipart(form)
        .send()?;
    Ok(resp.status().is_success())
}
