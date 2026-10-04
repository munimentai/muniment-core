//! Account credentials in OpenBao: one KV v2 secret per account.
//!
//! The secret at `<mount>/data/<prefix>/<account id>` holds the credential as
//! the router serializes it: `{"type":"api_key","key":…}` or
//! `{"type":"subscription","provider":…,"access":…,"refresh":…}`. Reads are
//! cached for a short time. A refreshed token is written back with a
//! check-and-set on the version it replaced, so two routers never overwrite
//! each other's rotation.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::config::Credential;
use crate::store::SecretSource;

/// How the router proves itself to OpenBao.
#[derive(Clone, PartialEq, Eq)]
pub enum Auth {
    Token(String),
    AppRole {
        mount: String,
        role_id: String,
        secret_id: String,
    },
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Token(_) => f.write_str("Token"),
            Self::AppRole { mount, role_id, .. } => f
                .debug_struct("AppRole")
                .field("mount", mount)
                .field("role_id", role_id)
                .finish_non_exhaustive(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Settings {
    /// `https://openbao.example:8200`, without a path.
    pub address: String,
    /// The KV v2 mount.
    pub mount: String,
    /// The path under the mount that holds one secret per account.
    pub prefix: String,
    pub auth: Auth,
    pub cache_ttl: Duration,
    pub timeout: Duration,
}

struct Login {
    token: String,
    /// When the router logs in again, ahead of the lease's end.
    renew_at: Option<Instant>,
}

struct Cached {
    credential: Option<Credential>,
    read_at: Instant,
}

pub struct OpenBao {
    settings: Settings,
    agent: ureq::Agent,
    login: Mutex<Option<Login>>,
    cache: Mutex<HashMap<String, Cached>>,
}

/// Whether an account id is safe as one path segment.
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id != "."
        && id != ".."
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

impl OpenBao {
    pub fn new(settings: Settings) -> Self {
        let agent = crate::http::agent_builder()
            .timeout(settings.timeout)
            .build();
        Self {
            settings,
            agent,
            login: Mutex::new(None),
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn url(&self, path: &str) -> String {
        format!(
            "{}/v1/{}",
            self.settings.address.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }

    fn secret_path(&self, kind: &str, id: &str) -> Result<String, String> {
        if !valid_id(id) {
            return Err(format!("The account id {id:?} cannot name a secret."));
        }
        let prefix = self.settings.prefix.trim_matches('/');
        let mount = self.settings.mount.trim_matches('/');
        Ok(if prefix.is_empty() {
            format!("{mount}/{kind}/{id}")
        } else {
            format!("{mount}/{kind}/{prefix}/{id}")
        })
    }

    /// The token to send, logging in through AppRole when none is current.
    fn token(&self, fresh: bool) -> Result<String, String> {
        let (mount, role_id, secret_id) = match &self.settings.auth {
            Auth::Token(token) => return Ok(token.clone()),
            Auth::AppRole {
                mount,
                role_id,
                secret_id,
            } => (mount, role_id, secret_id),
        };
        let mut login = self.login.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(current) = login.as_ref() {
            if !fresh && current.renew_at.is_none_or(|at| Instant::now() < at) {
                return Ok(current.token.clone());
            }
        }
        let path = format!("auth/{}/login", mount.trim_matches('/'));
        let (status, body) = read(
            self.agent
                .post(&self.url(&path))
                .send_json(json!({"role_id": role_id, "secret_id": secret_id})),
        )?;
        if status != 200 {
            return Err(format!("OpenBao refused the AppRole login ({status})."));
        }
        let token = body["auth"]["client_token"]
            .as_str()
            .filter(|token| !token.is_empty())
            .ok_or("OpenBao answered the AppRole login without a token.")?
            .to_owned();
        // Log in again at four fifths of the lease, so a turn never sends a
        // token in its last moments.
        let renew_at = body["auth"]["lease_duration"]
            .as_u64()
            .filter(|seconds| *seconds > 0)
            .map(|seconds| Instant::now() + Duration::from_millis(seconds * 800));
        *login = Some(Login {
            token: token.clone(),
            renew_at,
        });
        Ok(token)
    }

    /// One call with the current token, and one more with a fresh login when
    /// OpenBao says the token no longer serves.
    fn call(&self, method: &str, path: &str, body: Option<&Value>) -> Result<(u16, Value), String> {
        let mut fresh = false;
        loop {
            let token = self.token(fresh)?;
            let request = self
                .agent
                .request(method, &self.url(path))
                .set("X-Vault-Token", &token);
            let answer = read(match body {
                Some(body) => request.send_json(body.clone()),
                None => request.call(),
            })?;
            if answer.0 == 403 && !fresh && matches!(self.settings.auth, Auth::AppRole { .. }) {
                fresh = true;
                continue;
            }
            return Ok(answer);
        }
    }

    /// The stored credential and its version, past the cache.
    fn read_versioned(&self, id: &str) -> Result<Option<(Credential, u64)>, String> {
        let (status, body) = self.call("GET", &self.secret_path("data", id)?, None)?;
        match status {
            404 => return Ok(None),
            200 => {}
            _ => return Err(format!("OpenBao answered {status} to a credential read.")),
        }
        let data = &body["data"]["data"];
        if data.is_null() {
            return Ok(None);
        }
        let credential: Credential = serde_json::from_value(data.clone())
            .map_err(|_| format!("The OpenBao secret for {id} is not a credential."))?;
        let version = body["data"]["metadata"]["version"].as_u64().unwrap_or(0);
        Ok(Some((credential, version)))
    }

    /// Writes the credential. With `cas`, only over that version, and
    /// `Ok(false)` says another writer came first.
    fn write_versioned(
        &self,
        id: &str,
        credential: &Credential,
        cas: Option<u64>,
    ) -> Result<bool, String> {
        let mut body = json!({ "data": credential });
        if let Some(version) = cas {
            body["options"] = json!({ "cas": version });
        }
        let (status, answer) = self.call("POST", &self.secret_path("data", id)?, Some(&body))?;
        if (200..300).contains(&status) {
            self.remember(id, Some(credential.clone()));
            return Ok(true);
        }
        let mismatch = answer["errors"].as_array().is_some_and(|errors| {
            errors.iter().any(|error| {
                error
                    .as_str()
                    .is_some_and(|text| text.contains("check-and-set"))
            })
        });
        if cas.is_some() && status == 400 && mismatch {
            return Ok(false);
        }
        Err(format!("OpenBao answered {status} to a credential write."))
    }

    fn remember(&self, id: &str, credential: Option<Credential>) {
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).insert(
            id.to_owned(),
            Cached {
                credential,
                read_at: Instant::now(),
            },
        );
    }
}

fn read(result: Result<ureq::Response, ureq::Error>) -> Result<(u16, Value), String> {
    match result {
        Ok(response) => {
            let status = response.status();
            Ok((status, response.into_json().unwrap_or(Value::Null)))
        }
        Err(ureq::Error::Status(status, response)) => {
            Ok((status, response.into_json().unwrap_or(Value::Null)))
        }
        Err(ureq::Error::Transport(_)) => Err("OpenBao did not answer.".into()),
    }
}

impl SecretSource for OpenBao {
    fn read(&self, id: &str) -> Result<Option<Credential>, String> {
        if let Some(cached) = self
            .cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .filter(|cached| cached.read_at.elapsed() < self.settings.cache_ttl)
        {
            return Ok(cached.credential.clone());
        }
        let credential = self.read_versioned(id)?.map(|(credential, _)| credential);
        self.remember(id, credential.clone());
        Ok(credential)
    }

    fn write(&self, id: &str, credential: &Credential) -> Result<(), String> {
        self.write_versioned(id, credential, None).map(|_| ())
    }

    fn remove(&self, id: &str) -> Result<(), String> {
        let (status, _) = self.call("DELETE", &self.secret_path("metadata", id)?, None)?;
        if !(200..300).contains(&status) && status != 404 {
            return Err(format!(
                "OpenBao answered {status} to a credential removal."
            ));
        }
        self.remember(id, None);
        Ok(())
    }

    fn swap(
        &self,
        id: &str,
        previous: &Credential,
        next: &Credential,
    ) -> Result<Credential, String> {
        for _ in 0..3 {
            let Some((current, version)) = self.read_versioned(id)? else {
                return Err("The account was removed.".into());
            };
            if &current != previous {
                self.remember(id, Some(current.clone()));
                return Ok(current);
            }
            if self.write_versioned(id, next, Some(version))? {
                return Ok(next.clone());
            }
        }
        Err("Another router keeps rotating this credential.".into())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;

    /// A stand-in for OpenBao's KV v2 and AppRole routes, in memory.
    pub(crate) struct Mock {
        pub address: String,
        pub calls: Arc<Mutex<Vec<String>>>,
        pub secrets: Arc<Mutex<HashMap<String, (Value, u64)>>>,
    }

    pub(crate) fn mock(token_ttl: u64) -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let calls: Arc<Mutex<Vec<String>>> = Arc::default();
        let secrets: Arc<Mutex<HashMap<String, (Value, u64)>>> = Arc::default();
        let (seen, store) = (Arc::clone(&calls), Arc::clone(&secrets));
        std::thread::spawn(move || {
            let mut issued = 0;
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let mut parts = line.split_whitespace();
                let method = parts.next().unwrap_or("").to_owned();
                let path = parts.next().unwrap_or("").to_owned();
                let mut length = 0;
                let mut token = String::new();
                loop {
                    let mut header = String::new();
                    reader.read_line(&mut header).unwrap();
                    let header = header.trim_end();
                    if header.is_empty() {
                        break;
                    }
                    let (name, value) = header.split_once(':').unwrap();
                    match name.to_ascii_lowercase().as_str() {
                        "content-length" => length = value.trim().parse().unwrap(),
                        "x-vault-token" => token = value.trim().to_owned(),
                        _ => {}
                    }
                }
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                seen.lock().unwrap().push(format!("{method} {path}"));
                let (status, answer) = if path == "/v1/auth/approle/login" {
                    if body["secret_id"] == "right" {
                        issued += 1;
                        (
                            200,
                            json!({"auth": {"client_token": format!("t{issued}"), "lease_duration": token_ttl}}),
                        )
                    } else {
                        (400, json!({"errors": ["invalid secret id"]}))
                    }
                } else if token != format!("t{issued}") && token != "static" {
                    (403, json!({"errors": ["permission denied"]}))
                } else if let Some(key) = path.strip_prefix("/v1/kv/data/") {
                    let mut map = store.lock().unwrap();
                    match method.as_str() {
                        "GET" => match map.get(key) {
                            Some((data, version)) => (
                                200,
                                json!({"data": {"data": data, "metadata": {"version": version}}}),
                            ),
                            None => (404, json!({"errors": []})),
                        },
                        _ => {
                            let current = map.get(key).map(|(_, v)| *v).unwrap_or(0);
                            if body["options"]["cas"]
                                .as_u64()
                                .is_some_and(|cas| cas != current)
                            {
                                (
                                    400,
                                    json!({"errors": ["check-and-set parameter did not match the current version"]}),
                                )
                            } else {
                                map.insert(key.to_owned(), (body["data"].clone(), current + 1));
                                (200, json!({"data": {"version": current + 1}}))
                            }
                        }
                    }
                } else if let Some(key) = path.strip_prefix("/v1/kv/metadata/") {
                    store.lock().unwrap().remove(key);
                    (204, Value::Null)
                } else {
                    (404, json!({"errors": []}))
                };
                let payload = if answer.is_null() {
                    String::new()
                } else {
                    answer.to_string()
                };
                let mut stream = stream;
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{payload}",
                    payload.len()
                );
            }
        });
        Mock {
            address,
            calls,
            secrets,
        }
    }

    pub(crate) fn settings(address: &str, auth: Auth, ttl: Duration) -> Settings {
        Settings {
            address: address.into(),
            mount: "kv".into(),
            prefix: "router/accounts".into(),
            auth,
            cache_ttl: ttl,
            timeout: Duration::from_secs(5),
        }
    }

    fn approle(secret: &str) -> Auth {
        Auth::AppRole {
            mount: "approle".into(),
            role_id: "role".into(),
            secret_id: secret.into(),
        }
    }

    fn subscription(access: &str) -> Credential {
        Credential::Subscription {
            provider: "anthropic".into(),
            access: access.into(),
            refresh: Some("r1".into()),
            expires_ms: Some(10),
            account_id: None,
            email: Some("a@example.com".into()),
            plan: None,
            renews_at_ms: None,
        }
    }

    #[test]
    fn credentials_round_trip_through_kv_v2_with_approle_and_a_cache() {
        let mock = mock(3600);
        let bao = OpenBao::new(settings(
            &mock.address,
            approle("right"),
            Duration::from_secs(60),
        ));
        assert_eq!(bao.read("a1").unwrap(), None);
        bao.write("a1", &subscription("x1")).unwrap();
        assert_eq!(
            mock.secrets.lock().unwrap()["router/accounts/a1"].0["access"],
            "x1"
        );
        // The write filled the cache, so these reads cost no call.
        let before = mock.calls.lock().unwrap().len();
        assert_eq!(bao.read("a1").unwrap(), Some(subscription("x1")));
        assert_eq!(bao.read("a1").unwrap(), Some(subscription("x1")));
        assert_eq!(mock.calls.lock().unwrap().len(), before);
        // One login served every call.
        let logins = mock
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| call.contains("approle"))
            .count();
        assert_eq!(logins, 1);
        bao.remove("a1").unwrap();
        assert_eq!(bao.read("a1").unwrap(), None);
        assert!(mock.secrets.lock().unwrap().is_empty());
        assert!(bao.read("../escape").is_err());
    }

    #[test]
    fn a_stale_cache_reads_again_and_an_expired_login_logs_in_again() {
        let mock = mock(0);
        let bao = OpenBao::new(settings(&mock.address, approle("right"), Duration::ZERO));
        bao.write("a1", &Credential::ApiKey { key: "k1".into() })
            .unwrap();
        mock.secrets
            .lock()
            .unwrap()
            .get_mut("router/accounts/a1")
            .unwrap()
            .0 = json!({"type": "api_key", "key": "k2"});
        assert_eq!(
            bao.read("a1").unwrap(),
            Some(Credential::ApiKey { key: "k2".into() })
        );
        // The server forgets the token: the next call logs in again once.
        *bao.login.lock().unwrap() = Some(Login {
            token: "revoked".into(),
            renew_at: None,
        });
        assert!(bao.read("a1").unwrap().is_some());
        let refused = OpenBao::new(settings(&mock.address, approle("wrong"), Duration::ZERO));
        assert!(refused.read("a1").unwrap_err().contains("AppRole"));
        let token = OpenBao::new(settings(
            &mock.address,
            Auth::Token("static".into()),
            Duration::ZERO,
        ));
        assert!(token.read("a1").unwrap().is_some());
        assert!(!format!("{:?}", approle("right")).contains("right"));
    }

    #[test]
    fn a_refreshed_token_is_written_back_unless_another_router_rotated_it_first() {
        let mock = mock(3600);
        let bao = OpenBao::new(settings(
            &mock.address,
            approle("right"),
            Duration::from_secs(60),
        ));
        bao.write("a1", &subscription("old")).unwrap();
        assert_eq!(
            bao.swap("a1", &subscription("old"), &subscription("new"))
                .unwrap(),
            subscription("new")
        );
        assert_eq!(mock.secrets.lock().unwrap()["router/accounts/a1"].1, 2);
        // A second router still holding "old" keeps the newer token.
        let other = OpenBao::new(settings(
            &mock.address,
            approle("right"),
            Duration::from_secs(60),
        ));
        assert_eq!(
            other
                .swap("a1", &subscription("old"), &subscription("mine"))
                .unwrap(),
            subscription("new")
        );
        assert_eq!(
            mock.secrets.lock().unwrap()["router/accounts/a1"].0["access"],
            "new"
        );
        assert!(bao
            .swap("gone", &subscription("old"), &subscription("new"))
            .is_err());
    }
}
