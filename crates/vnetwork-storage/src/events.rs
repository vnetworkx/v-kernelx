use crate::transactions::{atomic_write_bytes, quarantine_bytes};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use vnetwork_core::events::verify_event_chain;
use vnetwork_types::*;

pub struct EventWal {
    path: PathBuf,
}

impl EventWal {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            path: data_dir.join("events.wal"),
        }
    }

    pub fn append_events(&self, events: &[LedgerEvent]) -> VResult<()> {
        if events.is_empty() {
            return Ok(());
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| VNetworkError::Storage(format!("open events.wal failed: {e}")))?;

        for ev in events {
            let line = serde_json::to_string(ev)
                .map_err(|e| VNetworkError::Serialization(e.to_string()))?;
            writeln!(file, "{line}")
                .map_err(|e| VNetworkError::Storage(format!("write events.wal failed: {e}")))?;
        }
        file.sync_all()
            .map_err(|e| VNetworkError::Storage(format!("sync events.wal failed: {e}")))?;
        Ok(())
    }

    pub fn read_all(&self) -> VResult<Vec<LedgerEvent>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let file = File::open(&self.path)
            .map_err(|e| VNetworkError::Storage(format!("read events.wal failed: {e}")))?;
        let reader = BufReader::new(file);
        let mut out = Vec::new();
        for (line_no, line) in reader.lines().enumerate() {
            let line = line.map_err(|e| VNetworkError::Storage(e.to_string()))?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let ev: LedgerEvent = serde_json::from_str(trimmed).map_err(|e| {
                VNetworkError::Storage(format!("corrupt events.wal line {}: {e}", line_no + 1))
            })?;
            out.push(ev);
        }
        verify_event_chain(&out)?;
        Ok(out)
    }

    /// Reads event WAL records cleanly. Only if the final non-empty bytes lack a trailing `\n`
    /// and fail parsing (provably interrupted trailing write), quarantines those trailing bytes into
    /// `forensic_quarantine/` and safely truncates back to the last complete newline-terminated line.
    /// Complete or mid-file corrupt lines always fail closed.
    pub fn read_all_with_trailing_recovery(
        &self,
        data_dir: &Path,
    ) -> VResult<(Vec<LedgerEvent>, Vec<String>)> {
        if !self.path.exists() {
            return Ok((Vec::new(), Vec::new()));
        }
        let raw_bytes = fs::read(&self.path)
            .map_err(|e| VNetworkError::Storage(format!("read events.wal failed: {e}")))?;
        if raw_bytes.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        let ends_with_newline = raw_bytes.ends_with(b"\n");
        let last_nl_pos = raw_bytes.iter().rposition(|&b| b == b'\n');

        let text = match std::str::from_utf8(&raw_bytes) {
            Ok(s) => s.to_string(),
            Err(_) => {
                if let Some(pos) = last_nl_pos {
                    let prefix_str = std::str::from_utf8(&raw_bytes[..=pos]).map_err(|e| {
                        VNetworkError::Storage(format!(
                            "corrupt UTF-8 inside committed events.wal prefix: {e}"
                        ))
                    })?;
                    let mut out = Vec::new();
                    for (idx, line) in prefix_str.lines().enumerate() {
                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            continue;
                        }
                        let ev: LedgerEvent = serde_json::from_str(trimmed).map_err(|e| {
                            VNetworkError::Storage(format!(
                                "corrupt events.wal line {}: {e}",
                                idx + 1
                            ))
                        })?;
                        out.push(ev);
                    }
                    verify_event_chain(&out)?;
                    let q = quarantine_bytes(
                        data_dir,
                        "trailing_incomplete_utf8",
                        "events.wal",
                        &raw_bytes[pos + 1..],
                    )?;
                    self.rewrite_all(&out)?;
                    return Ok((out, vec![q]));
                }
                return Err(VNetworkError::Storage(
                    "corrupt UTF-8 in events.wal with no complete newline delimiter".to_string(),
                ));
            }
        };

        let mut out = Vec::new();
        let mut quarantined = Vec::new();
        let segments: Vec<&str> = text.split_inclusive('\n').collect();
        let total = segments.len();
        for (idx, seg) in segments.into_iter().enumerate() {
            let is_final = idx + 1 == total;
            let has_newline = seg.ends_with('\n');
            let trimmed = seg.trim();
            if trimmed.is_empty() {
                continue;
            }
            match serde_json::from_str::<LedgerEvent>(trimmed) {
                Ok(ev) => out.push(ev),
                Err(e) => {
                    if is_final && !ends_with_newline && !has_newline {
                        verify_event_chain(&out)?;
                        let q = quarantine_bytes(
                            data_dir,
                            "trailing_incomplete_json",
                            "events.wal",
                            seg.as_bytes(),
                        )?;
                        quarantined.push(q);
                        self.rewrite_all(&out)?;
                        return Ok((out, quarantined));
                    }
                    return Err(VNetworkError::Storage(format!(
                        "corrupt events.wal line {}: {e}",
                        idx + 1
                    )));
                }
            }
        }
        verify_event_chain(&out)?;
        Ok((out, quarantined))
    }

    pub fn rewrite_all(&self, events: &[LedgerEvent]) -> VResult<()> {
        let mut buf = Vec::new();
        for ev in events {
            let line = serde_json::to_string(ev)
                .map_err(|e| VNetworkError::Serialization(e.to_string()))?;
            writeln!(buf, "{line}").map_err(|e| {
                VNetworkError::Storage(format!("serialize events.wal line failed: {e}"))
            })?;
        }
        atomic_write_bytes(&self.path, &buf)
    }
}
