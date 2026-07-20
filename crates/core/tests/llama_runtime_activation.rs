#![cfg(unix)]

use std::fs::File;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use muniment_core::llama::runtime::{
    acquire_runtime_for, resolve_runtime_for, LlamaRuntimeDescriptor, RuntimeArchiveError,
    RuntimeDownloadRequest, RuntimeDownloadResponse, RuntimeDownloadTransport,
};
use muniment_core::llama::{verify_model_artifact, ResidentModelDescriptor};
use muniment_core::sidecar::{ProbeOutcome, SidecarConfig, SidecarStatus, SidecarSupervisor};
use sha2::{Digest, Sha256};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "muniment-runtime-activation-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct InterruptedTransport {
    bytes: Vec<u8>,
    first: bool,
    offsets: Vec<u64>,
}
impl RuntimeDownloadTransport for InterruptedTransport {
    type Body = Cursor<Vec<u8>>;
    fn download(
        &mut self,
        request: &RuntimeDownloadRequest,
    ) -> Result<RuntimeDownloadResponse<Self::Body>, RuntimeArchiveError> {
        self.offsets.push(request.offset);
        let end = if self.first {
            self.first = false;
            self.bytes.len() / 2
        } else {
            self.bytes.len()
        };
        Ok(RuntimeDownloadResponse {
            status: if request.offset == 0 { 200 } else { 206 },
            content_range: (request.offset > 0).then_some((
                request.offset,
                self.bytes.len() as u64 - 1,
                self.bytes.len() as u64,
            )),
            body: Cursor::new(self.bytes[request.offset as usize..end].to_vec()),
        })
    }
}

fn runtime_archive(root: &Path) -> (Vec<u8>, LlamaRuntimeDescriptor) {
    let path = root.join("fixture.tar.gz");
    let encoder =
        flate2::write::GzEncoder::new(File::create(&path).unwrap(), flate2::Compression::default());
    let mut tar = tar::Builder::new(encoder);
    let script = b"#!/bin/sh\nwhile :; do sleep 1; done\n";
    let mut header = tar::Header::new_gnu();
    header.set_size(script.len() as u64);
    header.set_mode(0o755);
    header.set_cksum();
    tar.append_data(&mut header, "llama-b10068/llama-server", &script[..])
        .unwrap();
    tar.into_inner().unwrap().finish().unwrap();
    let bytes = std::fs::read(path).unwrap();
    let hash = Box::leak(format!("{:x}", Sha256::digest(&bytes)).into_boxed_str());
    (
        bytes.clone(),
        LlamaRuntimeDescriptor {
            revision: "fixture",
            archive: "fixture.tar.gz",
            byte_size: bytes.len() as u64,
            sha256: hash,
            top_level: "llama-b10068",
            executable: "llama-b10068/llama-server",
        },
    )
}

#[test]
fn verified_model_and_resumed_owned_runtime_reach_supervised_readiness() {
    let temp = Temp::new();
    let model_bytes = b"verified model fixture";
    let model = temp.0.join("model.gguf");
    std::fs::write(&model, model_bytes).unwrap();
    let model_hash = Box::leak(format!("{:x}", Sha256::digest(model_bytes)).into_boxed_str());
    verify_model_artifact(
        &model,
        &ResidentModelDescriptor {
            source_url: "https://example.invalid/model.gguf",
            license: "fixture",
            filename: "model.gguf",
            byte_size: model_bytes.len() as u64,
            sha256: model_hash,
            alias: "fixture",
            context_tokens: 8,
        },
    )
    .unwrap();

    let (bytes, descriptor) = runtime_archive(&temp.0);
    let mut transport = InterruptedTransport {
        bytes,
        first: true,
        offsets: Vec::new(),
    };
    let runtime_root = temp.0.join("runtime");
    let executable = acquire_runtime_for(
        &runtime_root,
        "https://example.invalid/release",
        &descriptor,
        &mut transport,
    )
    .unwrap();
    assert_eq!(transport.offsets.len(), 2);
    assert!(transport.offsets[1] > 0, "the interrupted archive resumed");
    assert_eq!(
        resolve_runtime_for(&runtime_root, &descriptor).unwrap(),
        executable
    );

    let mut config = SidecarConfig::new(executable.to_string_lossy());
    config.health_interval = Duration::from_millis(10);
    let mut supervisor = SidecarSupervisor::spawn(config, |_| Ok(ProbeOutcome::Ready)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while supervisor.status() != SidecarStatus::Healthy && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(supervisor.status(), SidecarStatus::Healthy);
    supervisor.shutdown().unwrap();

    std::fs::OpenOptions::new()
        .append(true)
        .open(&executable)
        .unwrap()
        .write_all(b"tampered")
        .unwrap();
    assert!(resolve_runtime_for(&runtime_root, &descriptor).is_err());
}
