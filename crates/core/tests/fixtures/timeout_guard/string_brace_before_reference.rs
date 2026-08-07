const STRING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_after_string_brace() {
        let value = "}";
        let _deadline = std::time::Instant::now() + STRING_TIMEOUT;
        assert_eq!(value, "}");
    }
}
