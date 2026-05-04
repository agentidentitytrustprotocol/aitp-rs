//! Subprocess-based adapter.
//!
//! Spawns an executable and exchanges NDJSON over stdin/stdout. Reads
//! one line per request with a configurable timeout (default 30s)
//! implemented via a worker thread + `mpsc::channel`.

use crate::adapter::{Adapter, AdapterError, AdapterInfo, OpResult};
use serde_json::json;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Subprocess adapter — spawns an executable and exchanges NDJSON.
pub struct SubprocessAdapter {
    process: Child,
    stdin: ChildStdin,
    /// `Some` until shut down (read by the worker thread).
    reader: Option<thread::JoinHandle<()>>,
    rx: mpsc::Receiver<std::io::Result<String>>,
    info: Option<AdapterInfo>,
    next_id: u64,
    timeout: Duration,
}

impl SubprocessAdapter {
    /// Spawn an adapter executable.
    ///
    /// `stderr` is inherited so adapter logs reach the runner's stderr.
    pub fn spawn(executable: &str, args: &[&str]) -> Result<Self, AdapterError> {
        let mut process = Command::new(executable)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let stdin = process.stdin.take().unwrap();
        let stdout = process.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel::<std::io::Result<String>>();
        let reader = thread::spawn(move || read_lines(stdout, tx));
        Ok(Self {
            process,
            stdin,
            reader: Some(reader),
            rx,
            info: None,
            next_id: 0,
            timeout: Duration::from_secs(30),
        })
    }

    /// Override the per-request timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn send_raw(
        &mut self,
        op: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, AdapterError> {
        self.next_id += 1;
        let id = format!("req-{}", self.next_id);
        let request = json!({"id": id, "op": op, "params": params});
        let line = format!("{}\n", request);
        self.stdin
            .write_all(line.as_bytes())
            .map_err(AdapterError::from)?;
        self.stdin.flush().ok();

        let recv = self.rx.recv_timeout(self.timeout);
        let line = match recv {
            Ok(Ok(l)) => l,
            Ok(Err(e)) => return Err(AdapterError::Io(e)),
            Err(mpsc::RecvTimeoutError::Timeout) => return Err(AdapterError::Timeout),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(AdapterError::ProcessDied("EOF on stdout".into()));
            }
        };
        if line.trim().is_empty() {
            return Err(AdapterError::ProcessDied("EOF on stdout".into()));
        }
        let response: serde_json::Value = serde_json::from_str(&line)
            .map_err(|e| AdapterError::MalformedResponse(e.to_string()))?;
        if response.get("id").and_then(|v| v.as_str()) != Some(&id) {
            return Err(AdapterError::MalformedResponse(format!(
                "id mismatch: expected {id}"
            )));
        }
        Ok(response)
    }
}

fn read_lines(stdout: ChildStdout, tx: mpsc::Sender<std::io::Result<String>>) {
    let mut buf = BufReader::new(stdout);
    loop {
        let mut line = String::new();
        match buf.read_line(&mut line) {
            Ok(0) => return,
            Ok(_) => {
                if tx.send(Ok(line)).is_err() {
                    return;
                }
            }
            Err(e) => {
                let _ = tx.send(Err(e));
                return;
            }
        }
    }
}

impl Adapter for SubprocessAdapter {
    fn init(&mut self) -> Result<AdapterInfo, AdapterError> {
        let response = self.send_raw("init", json!({"version": "1"}))?;
        let result = response
            .get("result")
            .cloned()
            .ok_or_else(|| AdapterError::MalformedResponse("init missing result".into()))?;
        let info: AdapterInfo = serde_json::from_value(result)
            .map_err(|e| AdapterError::MalformedResponse(e.to_string()))?;
        self.info = Some(info.clone());
        Ok(info)
    }

    fn execute(&mut self, op: &str, params: serde_json::Value) -> Result<OpResult, AdapterError> {
        if let Some(info) = &self.info {
            if !info.supported_ops.contains(op) {
                return Err(AdapterError::OpNotSupported(op.into()));
            }
        }
        let response = self.send_raw(op, params)?;
        let mut obj = response
            .as_object()
            .ok_or_else(|| AdapterError::MalformedResponse("response not object".into()))?
            .clone();
        obj.remove("id");
        let cleaned = serde_json::Value::Object(obj);
        serde_json::from_value(cleaned).map_err(|e| AdapterError::MalformedResponse(e.to_string()))
    }

    fn shutdown(&mut self) -> Result<(), AdapterError> {
        let _ = self.send_raw("shutdown", json!({}));
        for _ in 0..10 {
            if let Ok(Some(_)) = self.process.try_wait() {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        let _ = self.process.kill();
        let _ = self.process.wait();
        if let Some(handle) = self.reader.take() {
            let _ = handle.join();
        }
        Ok(())
    }
}

impl Drop for SubprocessAdapter {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}
