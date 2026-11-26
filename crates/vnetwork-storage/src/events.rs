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

    pub fn rewrite_all(&self, events: &[LedgerEvent]) -> VResult<()> {
        let tmp = self.path.with_extension("wal.tmp");
        {
            let mut file = File::create(&tmp)
                .map_err(|e| VNetworkError::Storage(format!("create events.wal.tmp failed: {e}")))?;
            for ev in events {
                let line = serde_json::to_string(ev)
                    .map_err(|e| VNetworkError::Serialization(e.to_string()))?;
                writeln!(file, "{line}")
                    .map_err(|e| VNetworkError::Storage(format!("write events.wal.tmp failed: {e}")))?;
            }
            file.sync_all()
                .map_err(|e| VNetworkError::Storage(format!("sync events.wal.tmp failed: {e}")))?;
        }
        fs::rename(&tmp, &self.path)
            .map_err(|e| VNetworkError::Storage(format!("rename events.wal failed: {e}")))?;
        Ok(())
    }
}
