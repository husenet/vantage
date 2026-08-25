//! Terminal-aware layout: width detection, ANSI-safe display width, and
//! word/attribute wrapping - so the output reads cleanly at any terminal size
//! instead of ruling to a fixed 64 columns and letting long cookie and header
//! values hard-wrap mid-token at the raw screen edge.

use std::io::IsTerminal;
use terminal_size::{terminal_size, Width};

/// Widest rule or line we draw, and the narrowest we bother adapting to. Below
/// the floor the terminal is too thin to lay out nicely anyway; above the cap a
/// full-width rule stops reading as a divider and a wrapped value runs too long
/// to scan.
const MIN: usize = 40;
const MAX: usize = 100;
/// Used when stdout is not a terminal (piped to a file, `less`, or `grep`),
/// where there is no width to ask for. A conventional terminal width.
const PIPED: usize = 80;

/// The usable output width: the real terminal width when stdout is one, clamped
/// to [`MIN`, `MAX`]; [`PIPED`] otherwise.
pub fn width() -> usize {
    let raw = if std::io::stdout().is_terminal() {
        terminal_size()
            .map(|(Width(w), _)| w as usize)
            .unwrap_or(PIPED)
    } else {
        PIPED
    };
    raw.clamp(MIN, MAX)
}

/// Visible column count of a styled string. ANSI SGR escapes (`\x1b[..m`, the
/// only kind vantage emits) are zero-width; every other char counts as one.
pub fn display_width(s: &str) -> usize {
    let mut n = 0;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for e in chars.by_ref() {
                if e == 'm' {
                    break;
                }
            }
        } else {
            n += 1;
        }
    }
    n
}

/// Wrap one already-styled line to `width` visible columns.
///
/// Preserves the line's leading indent, hangs continuations under it so a
/// wrapped value reads as one block, and breaks at spaces and after `;`/`,` -
/// the separators in cookie and header values - rather than mid-token. A single
/// run with no break in it (a long unbroken value) is hard-split at the width so
/// it still never overflows. Never splits inside an escape sequence, so color is
/// never corrupted. Returns the line untouched when it already fits.
pub fn wrap(line: &str, width: usize) -> Vec<String> {
    if display_width(line) <= width {
        return vec![line.to_string()];
    }

    // Leading spaces are literal ASCII (1 byte each), so the count is a valid
    // byte offset to slice at.
    let lead = line.chars().take_while(|&c| c == ' ').count();
    let indent = " ".repeat(lead);
    // Hang continuations a little deeper than the indent, unless that would
    // leave too little room to be worth it.
    let cont = if lead + 4 + 8 < width { lead + 4 } else { lead };
    let cont_indent = " ".repeat(cont);

    let chunks = chunk(&line[lead..]);
    let mut lines: Vec<String> = Vec::new();
    let mut cur = indent;
    let mut cur_w = lead;
    let mut ind_w = lead; // indent width of the line being built

    for ch in &chunks {
        // Fits nowhere useful on the current line: start a continuation.
        if cur_w + ch.w > width && cur_w > ind_w {
            lines.push(trim_end(&cur));
            cur = cont_indent.clone();
            cur_w = cont;
            ind_w = cont;
        }
        if ch.w > width.saturating_sub(ind_w) {
            // One chunk wider than a whole line (a long unbroken value): flush
            // anything pending, then hard-split it across lines. The first piece
            // keeps whatever indent the line already has, so a value that opens
            // an entry stays at the entry's indent instead of reading as a
            // continuation of the entry above it.
            let head_indent = if cur_w > ind_w {
                lines.push(trim_end(&cur));
                cont_indent.clone()
            } else {
                " ".repeat(ind_w)
            };
            let avail = width.saturating_sub(cont);
            let pieces = hard_split(&ch.text, avail);
            let last = pieces.len().saturating_sub(1);
            for (i, piece) in pieces.iter().enumerate() {
                let ind = if i == 0 { &head_indent } else { &cont_indent };
                if i == last {
                    // Keep the tail on the current line so the next chunk can
                    // continue after it.
                    cur = format!("{ind}{piece}");
                    ind_w = ind.len();
                    cur_w = ind_w + display_width(piece);
                } else {
                    lines.push(format!("{ind}{piece}"));
                }
            }
        } else {
            cur.push_str(&ch.text);
            cur_w += ch.w;
        }
    }
    if cur_w > ind_w {
        lines.push(trim_end(&cur));
    }
    lines
}

struct Chunk {
    text: String,
    w: usize,
}

/// Split a styled string into chunks that each end at a break opportunity -
/// after a space, `;`, or `,` - keeping any escape sequences whole.
fn chunk(s: &str) -> Vec<Chunk> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut w = 0;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            buf.push(c);
            for e in chars.by_ref() {
                buf.push(e);
                if e == 'm' {
                    break;
                }
            }
            continue;
        }
        buf.push(c);
        w += 1;
        if c == ' ' || c == ';' || c == ',' {
            out.push(Chunk {
                text: std::mem::take(&mut buf),
                w,
            });
            w = 0;
        }
    }
    if !buf.is_empty() {
        out.push(Chunk { text: buf, w });
    }
    out
}

/// Break a styled run into pieces of at most `avail` visible columns, never
/// inside an escape sequence.
fn hard_split(s: &str, avail: usize) -> Vec<String> {
    let avail = avail.max(1);
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut w = 0;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            buf.push(c);
            for e in chars.by_ref() {
                buf.push(e);
                if e == 'm' {
                    break;
                }
            }
            continue;
        }
        if w >= avail {
            out.push(std::mem::take(&mut buf));
            w = 0;
        }
        buf.push(c);
        w += 1;
    }
    if !buf.is_empty() {
        out.push(buf);
    }
    out
}

/// Drop trailing spaces left by a break after a space, without touching a
/// trailing escape sequence (spaces are literal, escapes end in a letter).
fn trim_end(s: &str) -> String {
    s.trim_end_matches(' ').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_width_ignores_ansi() {
        assert_eq!(display_width("\x1b[2mhello\x1b[0m"), 5);
        assert_eq!(display_width("plain"), 5);
        assert_eq!(display_width("\x1b[38;2;1;2;3mX\x1b[0m"), 1);
    }

    #[test]
    fn short_line_is_untouched() {
        assert_eq!(wrap("  a short line", 64), vec!["  a short line"]);
    }

    #[test]
    fn breaks_at_semicolons_and_keeps_them() {
        // A cookie-shaped value, no ANSI, narrow width.
        let out = wrap("  ARR=abcdef;Path=/;HttpOnly;Secure;Domain=example.net", 24);
        assert!(out.len() > 1, "should wrap: {out:?}");
        // Every visible line fits.
        assert!(out.iter().all(|l| display_width(l) <= 24), "{out:?}");
        // Nothing is lost: rejoining the trimmed pieces reproduces the tokens.
        let joined: String = out.iter().map(|l| l.trim()).collect::<Vec<_>>().join("");
        assert!(joined.contains("Domain=example.net"), "{joined}");
        // Attribute boundaries, not mid-token: a break lands right after a ';'.
        assert!(out[0].trim_end().ends_with(';'), "{out:?}");
    }

    #[test]
    fn hard_split_keeps_the_first_piece_at_the_entry_indent() {
        // A cookie whose name=value alone is wider than the terminal: the entry
        // must still open at its own indent, or it reads as a continuation of
        // the entry above it.
        let line = format!("  ARRAffinity={};Path=/;Secure", "a".repeat(80));
        let out = wrap(&line, 40);
        assert!(out[0].starts_with("  ARRAffinity="), "first line: {:?}", out[0]);
        assert!(!out[0].starts_with("      "), "first line hung: {:?}", out[0]);
        assert!(out[1].starts_with("      "), "cont not hung: {:?}", out[1]);
        assert!(out.iter().all(|l| display_width(l) <= 40), "{out:?}");
    }

    #[test]
    fn continuation_is_indented_under_the_start() {
        let out = wrap("  ARR=abcdef;Path=/;HttpOnly;Secure;Domain=example.net", 24);
        // Original indent is 2; continuations hang deeper.
        assert!(out[1].starts_with("      "), "cont not hung: {out:?}");
    }

    #[test]
    fn an_unbreakable_run_is_hard_split_not_overflowed() {
        let long = format!("  {}", "x".repeat(200));
        let out = wrap(&long, 40);
        assert!(out.iter().all(|l| display_width(l) <= 40), "{out:?}");
        let chars: usize = out.iter().map(|l| l.trim().len()).sum();
        assert_eq!(chars, 200, "no characters lost");
    }

    #[test]
    fn ansi_span_is_never_split_mid_escape() {
        // A single dim span wider than the width, as cookies.rs emits.
        let styled = format!("  \x1b[2m{}\x1b[0m", "ab;".repeat(40));
        let out = wrap(&styled, 30);
        for l in &out {
            // No line ends part-way through an escape (i.e. an ESC with no 'm').
            let esc = l.matches('\x1b').count();
            let terminators = l.matches('m').count();
            assert!(terminators >= esc, "escape split across a line: {l:?}");
        }
    }

    #[test]
    fn width_is_clamped() {
        assert!((MIN..=MAX).contains(&width()));
    }
}
