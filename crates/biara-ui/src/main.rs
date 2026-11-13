fn main() {
    // The analysis engine runs its worker pool as copies of this executable.
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() == Some("__worker") {
        let config = args.next().unwrap_or_default();
        if let Err(e) = biara_engine::worker(&config) {
            eprintln!("biara worker: {e}");
            std::process::exit(1);
        }
        return;
    }
    biara_ui::ui::run();
}
