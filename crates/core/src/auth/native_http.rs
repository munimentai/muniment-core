//! Native HTTP diagnostics omit bodies, credentials, and unrecognized error codes.

use crate::runtime_eprintln as eprintln;
use std::io::Read;
use std::time::Instant;

#[derive(Clone, PartialEq, Eq)]
pub struct NativeHttpFailure {
    code: Option<&'static str>,
    cf_ray: Option<String>,
    retry_after: Option<String>,
}

impl std::fmt::Debug for NativeHttpFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.diagnostic())
    }
}

impl NativeHttpFailure {
    pub fn code(&self) -> Option<&'static str> {
        self.code
    }

    pub(super) fn retry_after(&self) -> Option<&str> {
        self.retry_after.as_deref()
    }

    pub(super) fn from_response(response: ureq::Response) -> Self {
        // Accept only the edge's fixed identifier shape, never arbitrary header text.
        let cf_ray = response
            .header("cf-ray")
            .filter(|value| {
                let Some((id, colo)) = value.split_once('-') else {
                    return false;
                };
                id.len() == 16
                    && id.bytes().all(|b| b.is_ascii_hexdigit())
                    && colo.len() == 3
                    && colo.bytes().all(|b| b.is_ascii_uppercase())
            })
            .map(str::to_owned);
        let retry_after = response.header("Retry-After").map(str::to_owned);
        let mut body = Vec::new();
        let read = response.into_reader().take(8193).read_to_end(&mut body);
        let code = if read.is_ok() && body.len() <= 8192 {
            serde_json::from_slice::<serde_json::Value>(&body)
                .ok()
                .and_then(|body| {
                    // A character filter alone would let a token masquerade as an error code.
                    match body
                        .pointer("/error/code")
                        .and_then(serde_json::Value::as_str)
                    {
                        Some("invalid_request") => Some("invalid_request"),
                        Some("invalid_registration") => Some("invalid_registration"),
                        Some("invalid_client") => Some("invalid_client"),
                        Some("invalid_device_proof") => Some("invalid_device_proof"),
                        Some("invalid_grant") => Some("invalid_grant"),
                        Some("invalid_token") => Some("invalid_token"),
                        Some("unauthorized") => Some("unauthorized"),
                        Some("forbidden") => Some("forbidden"),
                        Some("rate_limited") => Some("rate_limited"),
                        Some("internal_error") => Some("internal_error"),
                        _ => None,
                    }
                })
        } else {
            None
        };
        Self {
            code,
            cf_ray,
            retry_after,
        }
    }

    pub(super) fn diagnostic(&self) -> String {
        format!(
            "error_code={} cf_ray={}",
            self.code.unwrap_or("unavailable"),
            self.cf_ray.as_deref().unwrap_or("unavailable")
        )
    }
}

pub(super) enum Error {
    Status(u16, NativeHttpFailure),
    Transport(ureq::Transport),
}

pub(super) fn request(
    method: &'static str,
    path: &'static str,
    send: impl FnOnce() -> Result<ureq::Response, Box<ureq::Error>>,
) -> Result<ureq::Response, Box<Error>> {
    let started = Instant::now();
    log(&format!(
        "muniment-runtime: native-auth start method={method} path={path}"
    ));
    let result = send().map_err(|error| {
        Box::new(match *error {
            ureq::Error::Status(status, response) => {
                Error::Status(status, NativeHttpFailure::from_response(response))
            }
            ureq::Error::Transport(error) => Error::Transport(error),
        })
    });
    log(&after_line(
        method,
        path,
        &result,
        started.elapsed().as_millis(),
    ));
    result
}

fn after_line(
    method: &str,
    path: &str,
    result: &Result<ureq::Response, Box<Error>>,
    elapsed_ms: u128,
) -> String {
    let outcome = match result.as_ref().map_err(Box::as_ref) {
        Ok(response) => format!("status={}", response.status()),
        Err(Error::Status(status, failure)) => format!("status={status} {}", failure.diagnostic()),
        // ErrorKind has no request data. Never format the transport error itself.
        Err(Error::Transport(error)) => format!("error={:?}", error.kind()),
    };
    format!(
        "muniment-runtime: native-auth end method={method} path={path} {outcome} elapsed_ms={elapsed_ms}"
    )
}

pub(super) fn log(line: &str) {
    eprintln!("{line}");
    #[cfg(test)]
    CAPTURE.with(|capture| {
        if let Some(lines) = capture.borrow_mut().as_mut() {
            lines.push(line.to_owned());
        }
    });
}

#[cfg(test)]
thread_local! {
    static CAPTURE: std::cell::RefCell<Option<Vec<String>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(super) fn capture<T>(step: impl FnOnce() -> T) -> (T, Vec<String>) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            CAPTURE.with(|capture| *capture.borrow_mut() = None);
        }
    }
    let _reset = Reset;
    CAPTURE.with(|capture| *capture.borrow_mut() = Some(Vec::new()));
    let result = step();
    let lines = CAPTURE.with(|capture| capture.borrow_mut().take().unwrap());
    (result, lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn after_line_has_a_stable_shape_for_status_and_transport_errors() {
        for status in [200, 201, 302, 401, 429, 500] {
            let response = ureq::Response::new(status, "ignored", "secret-body").unwrap();
            let result = if status >= 400 {
                Err(Box::new(Error::Status(
                    status,
                    NativeHttpFailure::from_response(response),
                )))
            } else {
                Ok(response)
            };
            assert_eq!(
                after_line("POST", "/v1/auth/native/authorize", &result, 17),
                format!("muniment-runtime: native-auth end method=POST path=/v1/auth/native/authorize status={status}{} elapsed_ms=17", if status >= 400 { " error_code=unavailable cf_ray=unavailable" } else { "" })
            );
        }
        let error = request("GET", "/v1/auth/native/session", || {
            ureq::get("not a URL: secret").call().map_err(Box::new)
        });
        assert_eq!(
            after_line("GET", "/v1/auth/native/session", &error, 0),
            "muniment-runtime: native-auth end method=GET path=/v1/auth/native/session error=InvalidUrl elapsed_ms=0"
        );
    }

    #[test]
    fn failure_metadata_rejects_secrets_malformed_bodies_and_oversized_bodies() {
        for body in [
            String::new(),
            "<html>secret-edge-page</html>".into(),
            r#"{"error":{"code":"secret_token"}}"#.into(),
            r#"{"error":{"code":"invalid_request\nsecret"}}"#.into(),
            r#"{"error":{"code":42}}"#.into(),
            r#"{"error":{"code":"invalid_request"}"#.into(),
            format!(
                r#"{{"error":{{"code":"invalid_request"}},"padding":"{}"}}"#,
                "x".repeat(8192)
            ),
        ] {
            let failure = NativeHttpFailure::from_response(
                ureq::Response::new(400, "ignored", &body).unwrap(),
            );
            assert_eq!(failure.code(), None);
            assert_eq!(
                failure.diagnostic(),
                "error_code=unavailable cf_ray=unavailable"
            );
        }
        for ray in [
            "secret-token",
            "0123456789abcdef-IAD secret",
            "0123456789abcde-IAD",
            "0123456789abcdef-iad",
        ] {
            let response: ureq::Response = format!("HTTP/1.1 400 Bad Request\r\nCF-Ray: {ray}\r\nRetry-After: secret-retry\r\n\r\n{{\"error\":{{\"code\":\"invalid_device_proof\"}}}}")
                .parse().unwrap();
            let failure = NativeHttpFailure::from_response(response);
            assert_eq!(failure.code(), Some("invalid_device_proof"));
            assert!(failure.diagnostic().ends_with("cf_ray=unavailable"));
            assert!(!format!("{failure:?}").contains("secret"));
        }
    }

    #[test]
    fn logs_start_before_send_and_end_after_a_transport_failure() {
        let (_, lines) = capture(|| {
            request("GET", "/v1/auth/native/devices", || {
                CAPTURE.with(|capture| assert_eq!(capture.borrow().as_ref().unwrap().len(), 1));
                ureq::get("not a URL").call().map_err(Box::new)
            })
        });
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0],
            "muniment-runtime: native-auth start method=GET path=/v1/auth/native/devices"
        );
        assert!(lines[1].contains("error=InvalidUrl elapsed_ms="));
    }
}
