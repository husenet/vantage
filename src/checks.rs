//! The individual checks. Each returns a Section of clean, severity-free output.

use crate::net::{self, Fetched, RateLimiter};
use crate::section::Section;
use crate::spin::Spinner;
use crate::style as s;
use std::process::Command;

const SECURITY_HEADERS: &[(&str, &str)] = &[
    ("strict-transport-security", "HSTS - forces HTTPS"),
    ("content-security-policy", "CSP - mitigates XSS / injection"),
    ("x-frame-options", "clickjacking protection"),
    ("x-content-type-options", "MIME-sniffing protection"),
    ("referrer-policy", "controls referrer leakage"),
    ("permissions-policy", "restricts powerful browser features"),
    ("cross-origin-opener-policy", "COOP"),
    ("cross-origin-embedder-policy", "COEP"),
    ("cross-origin-resource-policy", "CORP"),
];

pub fn headers(f: &Fetched) -> Section {
    let mut sec = Section::new("HTTP headers");
    let mut items: Vec<(String, String)> = f
        .headers
        .iter()
        .map(|(k, v)| (k.as_str().to_lowercase(), v.to_str().unwrap_or("").to_string()))
        .collect();
    items.sort_by(|a, b| a.0.cmp(&b.0));
    sec.text(s::dim(&format!("  {} response headers", items.len())));
    for (k, v) in &items {
        let vv = if v.chars().count() <= 100 {
            v.clone()
        } else {
            let head: String = v.chars().take(100).collect();
            format!("{head}...")
        };
        sec.text(format!("  {}: {}", s::magenta(k), s::dim(&vv)));
    }
    sec.text("");
    sec.text(s::bold("  security headers"));
    for (name, desc) in SECURITY_HEADERS {
        if f.get(name).is_some() {
            sec.good(name);
        } else {
            sec.bad(&format!("{name}  ({desc})"));
        }
    }
    sec
}

pub fn cookies(f: &Fetched) -> Section {
    let mut sec = Section::new("Cookies");
    let cks = f.get_all("set-cookie");
    if cks.is_empty() {
        sec.note("no Set-Cookie headers");
        return sec;
    }
    for c in &cks {
        let name = c.split('=').next().unwrap_or("").trim();
        let low = c.to_lowercase();
        let mut missing = Vec::new();
        if f.is_https && !low.contains("secure") {
            missing.push("Secure");
        }
        if !low.contains("httponly") {
            missing.push("HttpOnly");
        }
        if !low.contains("samesite") {
            missing.push("SameSite");
        }
        if missing.is_empty() {
            sec.good(&format!("{name} - Secure, HttpOnly, SameSite all set"));
        } else {
            sec.bad(&format!("{name} - missing {}", missing.join(", ")));
        }
    }
    sec
}

pub fn cors(f: &Fetched) -> Section {
    let mut sec = Section::new("CORS");
    let acao = match f.get("access-control-allow-origin") {
        None => {
            sec.note("no Access-Control-Allow-Origin header");
            return sec;
        }
        Some(v) => v,
    };
    sec.text(format!("  access-control-allow-origin: {}", s::dim(&acao)));
    if acao.trim() == "*" {
        let creds = f
            .get("access-control-allow-credentials")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false);
        if creds {
            sec.bad("wildcard origin (*) with credentials enabled - sensitive data exposure");
        } else {
            sec.bad("wildcard origin (*)");
        }
    } else {
        sec.good("origin is restricted");
    }
    sec
}

pub fn disclosure(f: &Fetched) -> Section {
    let mut sec = Section::new("Information disclosure");
    let mut any = false;
    for name in [
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "x-aspnetmvc-version",
        "x-generator",
        "via",
    ] {
        if let Some(v) = f.get(name) {
            any = true;
            sec.text(format!("  {}: {}", s::magenta(name), s::dim(&v)));
        }
    }
    if !any {
        sec.good("no server/framework headers disclosed");
    }
    sec
}

pub fn csp(f: &Fetched) -> Section {
    let mut sec = Section::new("Content-Security-Policy");
    let policy = match f.get("content-security-policy") {
        None => {
            if f.get("content-security-policy-report-only").is_some() {
                sec.bad("only Content-Security-Policy-Report-Only set (reports, does not enforce)");
            } else {
                sec.bad("no Content-Security-Policy header");
            }
            return sec;
        }
        Some(p) => p,
    };
    let mut dirs: Vec<(String, Vec<String>)> = Vec::new();
    for part in policy.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let toks: Vec<&str> = part.split_whitespace().collect();
        let name = toks[0].to_lowercase();
        let vals: Vec<String> = toks[1..].iter().map(|t| t.to_string()).collect();
        sec.text(format!("  {} {}", s::magenta(&name), s::dim(&vals.join(" "))));
        dirs.push((name, vals));
    }
    if !dirs.iter().any(|(n, _)| n == "default-src") {
        sec.bad("no default-src fallback");
    }
    for (name, vals) in &dirs {
        if !(name.ends_with("-src") || name == "default-src") {
            continue;
        }
        for v in vals {
            match v.as_str() {
                "'unsafe-inline'" => sec.bad(&format!(
                    "{name} allows 'unsafe-inline' (defeats much of CSP's XSS protection)"
                )),
                "'unsafe-eval'" => sec.bad(&format!("{name} allows 'unsafe-eval'")),
                "*" => sec.bad(&format!("{name} uses wildcard *")),
                "http:" => sec.bad(&format!("{name} allows insecure http: sources")),
                _ => {}
            }
        }
    }
    sec
}

pub fn hsts(f: &Fetched) -> Section {
    let mut sec = Section::new("HSTS (Strict-Transport-Security)");
    let v = match f.get("strict-transport-security") {
        None => {
            sec.bad("no Strict-Transport-Security header");
            return sec;
        }
        Some(v) => v,
    };
    sec.text(format!("  {}", s::dim(&v)));
    let mut max_age: Option<i64> = None;
    let mut inc = false;
    let mut pre = false;
    for part in v.split(';') {
        let p = part.trim().to_lowercase();
        if let Some(rest) = p.strip_prefix("max-age=") {
            max_age = rest.trim().parse::<i64>().ok();
        } else if p == "includesubdomains" {
            inc = true;
        } else if p == "preload" {
            pre = true;
        }
    }
    match max_age {
        None => sec.bad("no valid max-age"),
        Some(0) => sec.bad("max-age=0 disables HSTS"),
        Some(ma) if ma < 15_768_000 => sec.bad(&format!(
            "max-age={ma} (~{}d) is short; >= 6 months recommended",
            ma / 86400
        )),
        Some(ma) => sec.good(&format!("max-age={ma} (~{}d)", ma / 86400)),
    }
    if inc {
        sec.good("includeSubDomains set");
    } else {
        sec.bad("includeSubDomains not set");
    }
    if pre {
        sec.good("preload set");
    } else {
        sec.note("preload not set");
    }
    sec
}

pub fn methods(
    url: &str,
    active: bool,
    timeout: f64,
    insecure: bool,
    rate: &mut RateLimiter,
) -> Section {
    let mut sec = Section::new("HTTP methods");
    let allow = net::request("OPTIONS", url, timeout, insecure, rate)
        .ok()
        .and_then(|r| {
            r.headers()
                .get("allow")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        });
    match &allow {
        Some(a) => sec.text(format!("  Allow: {a}")),
        None => sec.text("  Allow: (none returned to OPTIONS)"),
    }

    let mut probe = vec!["GET", "HEAD", "OPTIONS", "TRACE"];
    if active {
        probe.extend(["POST", "PUT", "DELETE", "PATCH"]);
    }
    for m in probe {
        let code = net::request(m, url, timeout, insecure, rate)
            .map(|r| r.status().as_u16())
            .unwrap_or(0);
        let allowed = !matches!(code, 405 | 501 | 0);
        let mark = if allowed {
            s::green("allowed")
        } else {
            s::dim("blocked")
        };
        sec.text(format!("  {}  {}  {}", mark, code, s::bold(m)));
        if m == "TRACE" && allowed {
            sec.bad("TRACE accepted (Cross-Site Tracing / XST risk)");
        }
        if matches!(m, "POST" | "PUT" | "DELETE" | "PATCH") && allowed {
            sec.bad(&format!("{m} accepted (confirm it is intended and authorized)"));
        }
    }
    if !active {
        sec.note("POST/PUT/DELETE/PATCH not probed; pass --active to include them");
    }
    sec
}

pub fn dnsrecon(host: &str) -> Section {
    let mut sec = Section::new(format!("DNS records ({host})"));
    let keywords = [
        "internet address",
        "has address",
        "ipv6 address",
        "mail exchanger",
        "nameserver",
        "name server",
        "text =",
        "canonical name",
        "origin =",
        "addresses:", // Windows nslookup (plural)
        "address:",   // Linux nslookup (singular answer line)
    ];
    let spin = Spinner::start("resolving DNS records");
    let mut found = false;
    let mut last_err = String::new();
    for t in ["A", "AAAA", "NS", "MX", "TXT", "SOA", "CNAME"] {
        let out = match Command::new("nslookup")
            .arg(format!("-type={t}"))
            .arg(host)
            .output()
        {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                drop(spin);
                sec.bad("nslookup not found on PATH (e.g. sudo apt install dnsutils)");
                return sec;
            }
            Err(e) => {
                last_err = e.to_string();
                continue;
            }
        };
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if let Some(line) = stderr.lines().map(str::trim).find(|l| !l.is_empty()) {
                last_err = line.to_string();
            }
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        // The resolver banner is a "Server:" line followed by its "Address:"
        // line. A real A/AAAA answer is singular "Address:" on Linux but
        // plural "Addresses:" on Windows, while the banner address is singular
        // on both - so we drop only the address line that follows "Server:"
        // (plus anything carrying the ":53" resolver port on Linux).
        let mut prev_server = false;
        for line in stdout.lines() {
            let l = line.trim();
            let low = l.to_lowercase();
            if low.starts_with("server:") {
                prev_server = true;
                continue;
            }
            let banner_addr = prev_server && low.starts_with("address");
            prev_server = false;
            if l.contains("#53") || banner_addr {
                continue;
            }
            if keywords.iter().any(|k| low.contains(k)) {
                found = true;
                sec.text(format!("  {} {}", s::cyan(&format!("{t:<5}")), l));
            }
        }
    }
    drop(spin);
    if !found {
        sec.bad("no records resolved");
        if !last_err.is_empty() {
            sec.note(&last_err);
        }
    }
    sec
}

pub fn nmap(host: &str, vulners: bool) -> Section {
    let title = format!(
        "{} ({host})",
        if vulners {
            "nmap --script vulners"
        } else {
            "nmap service scan"
        }
    );
    let mut sec = Section::new(title);
    let ports = "80,443,8080,8443,8000,8008,8888,3000,5000,9000";

    let mut args: Vec<String> = vec!["-Pn".into(), "-sV".into(), "-p".into(), ports.into()];
    if vulners {
        args.push("--script".into());
        args.push("vulners".into());
    }
    args.push(host.to_string());
    // Show the exact command being run, so a report reader can reproduce it.
    sec.text(format!("  {}", s::dim(&format!("$ nmap {}", args.join(" ")))));

    let spin = Spinner::start("running nmap (this can take a while)");
    let result = Command::new("nmap").args(&args).output();
    drop(spin);

    let out = match result {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            sec.bad("nmap not installed / not on PATH (e.g. sudo apt install nmap)");
            return sec;
        }
        Err(e) => {
            sec.bad(&format!("nmap failed to launch: {e}"));
            return sec;
        }
    };

    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut printed = 0;
    for line in stdout.lines() {
        let l = line.trim_end();
        if l.is_empty() {
            continue;
        }
        if l.contains("/tcp")
            || l.starts_with("PORT")
            || l.contains("CVE-")
            || l.starts_with('|')
            || l.starts_with("Service Info")
        {
            sec.text(format!("  {l}"));
            printed += 1;
        }
    }

    // Error checking: a non-zero exit or no parseable results means the scan did
    // not really run - surface nmap's own stderr so the failure is visible.
    if !out.status.success() || printed == 0 {
        if !out.status.success() {
            let code = out
                .status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "signal".into());
            sec.bad(&format!("nmap exited with status {code}"));
        } else {
            sec.bad("nmap returned no scan results");
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        for line in stderr.lines().map(str::trim).filter(|l| !l.is_empty()).take(5) {
            sec.note(line);
        }
        return sec;
    }

    if vulners {
        let cves = stdout.lines().filter(|x| x.contains("CVE-")).count();
        if cves > 0 {
            sec.bad(&format!(
                "{cves} CVE line(s) reported by vulners - review the output"
            ));
        } else {
            sec.good("no CVEs reported for the detected service versions");
        }
    }
    sec
}
