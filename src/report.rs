//! Report export: render the collected sections to a Markdown or HTML file.
//!
//! Section lines are built with ANSI styling baked in for the terminal, so we
//! strip it here to keep report files clean regardless of the color setting.

use crate::section::Section;

/// Output format, inferred from the report file's extension.
pub enum Format {
    Markdown,
    Html,
}

impl Format {
    /// `.html`/`.htm` -> HTML; anything else -> Markdown.
    pub fn from_path(path: &str) -> Format {
        let low = path.to_lowercase();
        if low.ends_with(".html") || low.ends_with(".htm") {
            Format::Html
        } else {
            Format::Markdown
        }
    }
}

/// One scanned target's results, borrowed for rendering.
pub struct TargetReport<'a> {
    pub target: &'a str,
    pub host: &'a str,
    pub status: Option<u16>,
    pub sections: &'a [Section],
}

pub fn render(format: &Format, results: &[TargetReport]) -> String {
    match format {
        Format::Markdown => markdown(results),
        Format::Html => html(results),
    }
}

/// Remove ANSI SGR escape sequences (`\x1b[...m`) - the only kind vantage emits.
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Consume up to and including the terminating 'm'.
            for n in chars.by_ref() {
                if n == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn markdown(results: &[TargetReport]) -> String {
    let mut o = String::new();
    o.push_str("# vantage report\n\n");
    for r in results {
        o.push_str(&format!("## {}\n\n", r.target));
        if r.host != r.target {
            o.push_str(&format!("Host: `{}`\n\n", r.host));
        }
        if let Some(s) = r.status {
            o.push_str(&format!("HTTP {s}\n\n"));
        }
        for sec in r.sections {
            o.push_str(&format!("### {}\n\n```\n", sec.title));
            for line in &sec.lines {
                o.push_str(strip_ansi(line).trim_end());
                o.push('\n');
            }
            o.push_str("```\n\n");
        }
    }
    o
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn html(results: &[TargetReport]) -> String {
    let mut o = String::new();
    o.push_str(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
<title>vantage report</title>\n<style>\n\
:root{color-scheme:light dark}\n\
body{font:14px/1.5 system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem}\n\
h1{font-size:1.5rem}h2{margin-top:2.5rem;border-bottom:1px solid #8886;padding-bottom:.3rem}\n\
h3{margin:1.5rem 0 .5rem;font-size:1rem}\n\
.meta{color:#888}\n\
pre{background:#8881;border-radius:6px;padding:.8rem 1rem;overflow-x:auto;white-space:pre-wrap;word-break:break-word}\n\
.good{color:#1a7f37}.bad{color:#cf222e}.note{color:#888}\n\
</style>\n</head>\n<body>\n",
    );
    o.push_str("<h1>vantage report</h1>\n");
    for r in results {
        o.push_str(&format!("<h2>{}</h2>\n", esc(r.target)));
        let mut meta = Vec::new();
        if r.host != r.target {
            meta.push(format!("host {}", esc(r.host)));
        }
        if let Some(s) = r.status {
            meta.push(format!("HTTP {s}"));
        }
        if !meta.is_empty() {
            o.push_str(&format!("<p class=\"meta\">{}</p>\n", meta.join(" &middot; ")));
        }
        for sec in r.sections {
            o.push_str(&format!("<h3>{}</h3>\n<pre>", esc(&sec.title)));
            for line in &sec.lines {
                let plain = strip_ansi(line);
                let trimmed = plain.trim_start();
                let text = esc(plain.trim_end());
                if trimmed.starts_with("+ ") {
                    o.push_str(&format!("<span class=\"good\">{text}</span>\n"));
                } else if trimmed.starts_with("- ") {
                    o.push_str(&format!("<span class=\"bad\">{text}</span>\n"));
                } else {
                    o.push_str(&format!("{text}\n"));
                }
            }
            o.push_str("</pre>\n");
        }
    }
    o.push_str("</body>\n</html>\n");
    o
}
