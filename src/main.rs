//! vantage - web security scanner. For authorized testing only.

mod checks;
mod cli;
mod net;
mod section;
mod spin;
mod style;

fn main() {
    // Restore the terminal cursor (which the spinner may hide) on Ctrl-C.
    let _ = ctrlc::set_handler(|| {
        use std::io::Write;
        let mut err = std::io::stderr();
        let _ = write!(err, "\r\x1b[?25h");
        let _ = err.flush();
        std::process::exit(130);
    });
    std::process::exit(cli::run());
}
