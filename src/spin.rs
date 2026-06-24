//! A minimal stderr spinner shown while a slow external tool runs.
//!
//! It animates on stderr so it never pollutes stdout (section output / --json),
//! and it is a no-op unless stderr is a real terminal - so piped output, sample
//! captures, and JSON stay perfectly clean.

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

const FRAMES: [char; 4] = ['|', '/', '-', '\\'];

pub struct Spinner {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    label_len: usize,
}

impl Spinner {
    /// Start spinning with the given label. Returns an inert handle when stderr
    /// is not a TTY, so non-interactive output is untouched.
    pub fn start(label: &str) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let label_len = label.chars().count();
        if !std::io::stderr().is_terminal() {
            return Spinner {
                stop,
                handle: None,
                label_len,
            };
        }
        // Hide the terminal cursor so it does not blink at the end of the line.
        {
            let mut err = std::io::stderr();
            let _ = write!(err, "\x1b[?25l");
            let _ = err.flush();
        }
        let label = label.to_string();
        let flag = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            let mut err = std::io::stderr();
            let mut i = 0usize;
            while !flag.load(Ordering::Relaxed) {
                let _ = write!(err, "\r  {} {} ", FRAMES[i % FRAMES.len()], label);
                let _ = err.flush();
                i += 1;
                thread::sleep(Duration::from_millis(90));
            }
        });
        Spinner {
            stop,
            handle: Some(handle),
            label_len,
        }
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
            // Erase the spinner line and restore the terminal cursor.
            let mut err = std::io::stderr();
            let _ = write!(err, "\r{}\r\x1b[?25h", " ".repeat(self.label_len + 6));
            let _ = err.flush();
        }
    }
}
