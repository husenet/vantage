//! Output model: a Section is a titled block of lines, rendered as clean,
//! separated, severity-free output suited to report screenshots.

use crate::style as s;
use crate::term;

pub struct Section {
    pub title: String,
    pub lines: Vec<String>,
}

impl Section {
    pub fn new(title: impl Into<String>) -> Self {
        Section {
            title: title.into(),
            lines: Vec::new(),
        }
    }

    /// Raw, already-formatted line.
    pub fn text(&mut self, line: impl Into<String>) {
        self.lines.push(line.into());
    }

    pub fn good(&mut self, line: &str) {
        self.lines.push(format!("  {} {}", s::green("+"), line));
    }

    pub fn bad(&mut self, line: &str) {
        self.lines.push(format!("  {} {}", s::red("-"), line));
    }

    pub fn note(&mut self, line: &str) {
        self.lines.push(format!("    {}", s::dim(line)));
    }
}

pub fn print_section(sec: &Section) {
    let width = term::width();
    let head = format!("== {} ", sec.title);
    let pad = "=".repeat(width.saturating_sub(term::display_width(&head)));
    println!();
    println!("{}", s::bold(&format!("{head}{pad}")));
    for line in &sec.lines {
        for out in term::wrap(line, width) {
            println!("{out}");
        }
    }
}
