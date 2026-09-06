//! Native HTTP diagnostics contain only fixed labels, status codes, and durations.

use std::time::Instant;

pub(super) fn request(
    method: &'static str,
    path: &'static str,
    send: impl FnOnce() -> Result<ureq::Response, Box<ureq::Error>>,
) -> Result<ureq::Response, Box<ureq::Error>> {
    let started = Instant::now();
    log(&format!(
        "muniment-runtime: native-auth start method={method} path={path}"
    ));
    let result = send();
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
    result: &Result<ureq::Response, Box<ureq::Error>>,
    elapsed_ms: u128,
) -> String {
    let outcome = match result.as_ref().map_err(Box::as_ref) {
        Ok(response) | Err(ureq::Error::Status(_, response)) => {
            format!("status={}", response.status())
        }
        // ErrorKind has no request data. Never format the transport error itself.
        Err(ureq::Error::Transport(error)) => format!("error={:?}", error.kind()),
    };
    format!(
        "muniment-runtime: native-auth end method={method} path={path} {outcome} elapsed_ms={elapsed_ms}"
    )
}

fn log(line: &str) {
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
                Err(Box::new(ureq::Error::Status(status, response)))
            } else {
                Ok(response)
            };
            assert_eq!(
                after_line("POST", "/v1/auth/native/authorize", &result, 17),
                format!("muniment-runtime: native-auth end method=POST path=/v1/auth/native/authorize status={status} elapsed_ms=17")
            );
        }
        let error = ureq::get("not a URL: secret").call().map_err(Box::new);
        assert_eq!(
            after_line("GET", "/v1/auth/native/session", &error, 0),
            "muniment-runtime: native-auth end method=GET path=/v1/auth/native/session error=InvalidUrl elapsed_ms=0"
        );
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
