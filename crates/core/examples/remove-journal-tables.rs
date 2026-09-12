//! Build missing-table fixtures for runtime journal tests without a direct SQLite dependency.

fn main() {
    let mut args = std::env::args_os().skip(1);
    let path = args.next().expect("the journal fixture needs a path");
    let connection = rusqlite::Connection::open(path).unwrap();
    for table in args {
        let sql = match table.to_str().unwrap() {
            "events" => "DROP TABLE events",
            "thread_events" => "DROP TABLE thread_events",
            "run_threads" => "DROP TABLE run_threads",
            "run_workspaces" => "DROP TABLE run_workspaces",
            _ => panic!("the journal fixture table is invalid"),
        };
        connection.execute_batch(sql).unwrap();
    }
}
