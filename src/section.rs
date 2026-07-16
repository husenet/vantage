//! Output model: a Section is a titled block of lines, rendered as clean,
//! separated, severity-free output suited to report screenshots.

use crate::style as s;

const WIDTH: usize = 64;

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
    let head = format!("== {} ", sec.title);
    let pad = "=".repeat(WIDTH.saturating_sub(head.chars().count()));
    println!();
    println!("{}", s::bold(&format!("{head}{pad}")));
    for line in &sec.lines {
        println!("{line}");
    }
}
