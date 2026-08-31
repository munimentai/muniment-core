fn main() {
    assert!(std::env::args_os().nth(1).is_none());
    loop {
        std::thread::park();
    }
}
