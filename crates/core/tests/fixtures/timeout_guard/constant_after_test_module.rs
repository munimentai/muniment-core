#[cfg(test)]
mod first_tests {
    #[test]
    fn unrelated_test() {}
}

const LATE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

#[cfg(test)]
mod later_tests {
    use super::*;

    #[test]
    fn late_reference() {
        let _deadline = std::time::Instant::now() + LATE_TIMEOUT;
    }
}
