use std::time::Duration;

const DEFAULT_TIMEOUT: Duration = Duration::from_millis(250);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inherits_the_timeout() {
        let _deadline = std::time::Instant::now() + DEFAULT_TIMEOUT;
    }
}
