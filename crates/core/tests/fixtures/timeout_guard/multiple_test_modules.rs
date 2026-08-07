const SHARED_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

#[cfg(test)]
mod first_tests {
    use super::*;

    #[test]
    fn first_reference() {
        let _deadline = std::time::Instant::now() + SHARED_TIMEOUT;
    }
}

#[cfg(test)]
mod second_tests {
    use super::*;

    #[test]
    fn second_reference() {
        let _deadline = std::time::Instant::now() + SHARED_TIMEOUT;
    }
}
