//! Tiny ANSI styling helpers with a global on/off switch (no extra deps).

use std::sync::atomic::{AtomicBool, Ordering};

static COLOR: AtomicBool = AtomicBool::new(false);

pub fn set_color(enabled: bool) {
    COLOR.store(enabled, Ordering::Relaxed);
}

fn w(code: &str, text: &str) -> String {
    if COLOR.load(Ordering::Relaxed) {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

pub fn bold(t: &str) -> String {
    w("1", t)
}
pub fn dim(t: &str) -> String {
    w("2", t)
}
pub fn red(t: &str) -> String {
    w("31", t)
}
pub fn green(t: &str) -> String {
    w("32", t)
}
pub fn magenta(t: &str) -> String {
    w("35", t)
}
pub fn cyan(t: &str) -> String {
    w("36", t)
}

/// 24-bit foreground color, for the startup banner gradient.
pub fn rgb(r: u8, g: u8, b: u8, t: &str) -> String {
    if COLOR.load(Ordering::Relaxed) {
        format!("\x1b[38;2;{r};{g};{b}m{t}\x1b[0m")
    } else {
        t.to_string()
    }
}
