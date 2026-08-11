use std::ffi::OsString;
use std::sync::Mutex;

use muniment_core::auth::api_base_url;

static ENVIRONMENT: Mutex<()> = Mutex::new(());

struct Environment {
    api_base_url: Option<OsString>,
    issuer: Option<OsString>,
}

impl Environment {
    fn save() -> Self {
        Self {
            api_base_url: std::env::var_os("MUNIMENT_API_BASE_URL"),
            issuer: std::env::var_os("MUNIMENT_ISSUER"),
        }
    }
}

impl Drop for Environment {
    fn drop(&mut self) {
        restore("MUNIMENT_API_BASE_URL", self.api_base_url.take());
        restore("MUNIMENT_ISSUER", self.issuer.take());
    }
}

fn restore(key: &str, value: Option<OsString>) {
    match value {
        Some(value) => std::env::set_var(key, value),
        None => std::env::remove_var(key),
    }
}

#[test]
fn resolves_api_base_url_from_environment() {
    let _environment = ENVIRONMENT.lock().unwrap();
    let _saved = Environment::save();

    std::env::remove_var("MUNIMENT_API_BASE_URL");
    std::env::remove_var("MUNIMENT_ISSUER");
    assert_eq!(api_base_url(), "https://api.muniment.ai");

    std::env::set_var("MUNIMENT_ISSUER", "https://issuer.example.com");
    assert_eq!(api_base_url(), "https://issuer.example.com");

    std::env::set_var("MUNIMENT_API_BASE_URL", "https://api.example.com");
    assert_eq!(api_base_url(), "https://api.example.com");

    std::env::remove_var("MUNIMENT_ISSUER");
    assert_eq!(api_base_url(), "https://api.example.com");
}
