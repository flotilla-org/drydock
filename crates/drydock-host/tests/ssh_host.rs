//! What the `ssh_host` module decides without its machine. Everything it
//! does over SSH is checked live, against a lab machine, by conformance.
use drydock_host::{
    module::{Credentials, HttpClient, Module, Provider},
    ssh_host::SshHostModule,
};
use drydock_protocol::*;
use hegel::generators as gs;
use std::sync::Arc;

struct NoHttp;
#[async_trait::async_trait]
impl HttpClient for NoHttp {
    async fn execute(&self, _: reqwest::Request, _: &rigging_http_client::ChannelLabel) -> Result<http::Response<bytes::Bytes>, String> {
        Err("ssh_host makes no HTTP calls".into())
    }
}

async fn configured(settings: serde_json::Value) -> Result<Arc<dyn Provider>, ProtocolError> {
    let configuration = ProviderConfiguration {
        module: "ssh_host".into(),
        settings: serde_json::from_value(settings).unwrap(),
        credential: None,
        ..Default::default()
    };
    SshHostModule.configure("b1", &configuration, Arc::new(NoHttp)).await
}
fn machine() -> serde_json::Value {
    serde_json::json!({
        "address": "b1.lab.example.net", "port": 22, "user": "drydock", "host_key": "ssh-ed25519 AAAA",
        "identity_file": "/nonexistent/b1_ed25519",
    })
}

// The endpoint settings and the key file's absolute path are required, with
// nothing guessed, and unknown keys are refused; the instance takes no
// credential, and readiness says when the key file cannot be read, before it
// connects anywhere.
#[tokio::test]
async fn an_instance_names_its_machine_and_its_key_file() {
    for key in ["address", "port", "user", "host_key", "identity_file"] {
        let mut settings = machine();
        settings.as_object_mut().unwrap().remove(key);
        assert!(matches!(configured(settings).await, Err(ProtocolError::Refused { .. })), "without {key}");
    }
    let mut settings = machine();
    settings["identity_file"] = "b1_ed25519".into();
    assert!(matches!(configured(settings).await, Err(ProtocolError::Refused { .. })), "a relative key file");
    let mut settings = machine();
    settings["password"] = "hunter2".into();
    assert!(matches!(configured(settings).await, Err(ProtocolError::Refused { .. })), "an unknown key");

    let p = configured(machine()).await.unwrap();
    assert!(matches!(p.readiness(&Credentials::default()), Readiness::MissingCredential { .. }), "no key file");
    let key = tempfile::NamedTempFile::new().unwrap();
    let mut settings = machine();
    settings["identity_file"] = key.path().to_str().unwrap().into();
    let p = configured(settings).await.unwrap();
    assert!(!matches!(p.readiness(&Credentials::default()), Readiness::MissingCredential { .. }), "a readable key file");
}

// The vessels' directory is used in the machine's shell commands, the agent's
// unit and the session's socket forwards, so it is accepted exactly when it is
// absolute and holds nothing a shell, systemd or a forward reads specially. Each
// case draws an absolute path of ordinary segments (empty ones included), which
// is accepted; the same path made relative, or with any one special character
// put at a drawn place, is refused.
#[hegel::test]
fn the_directory_is_accepted_only_when_commands_and_forwards_take_it_as_it_is(tc: hegel::TestCase) {
    const ORDINARY: [char; 7] = ['a', 'Z', '0', '-', '.', '_', '/'];
    const SPECIAL: [char; 11] = [' ', '\t', '\n', ':', '\'', '"', '\\', '`', '$', '%', '\u{7f}'];
    let length = tc.draw(gs::integers::<usize>().min_value(0).max_value(10));
    let mut directory = "/".to_owned();
    for _ in 0..length {
        directory.push(ORDINARY[tc.draw(gs::integers::<usize>().min_value(0).max_value(ORDINARY.len() - 1))]);
    }
    let at = tc.draw(gs::integers::<usize>().min_value(1).max_value(directory.len()));
    let accepted = |directory: &str| {
        let mut settings = machine();
        settings["directory"] = directory.into();
        tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(configured(settings)).is_ok()
    };
    assert!(accepted(&directory), "{directory:?}");
    assert!(!accepted(directory.trim_start_matches('/')), "relative {directory:?}");
    for special in SPECIAL {
        let mut changed = directory.clone();
        changed.insert(at, special);
        assert!(!accepted(&changed), "{changed:?}");
    }
}
