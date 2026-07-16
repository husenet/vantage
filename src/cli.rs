//! Command-line interface: flag parsing and check orchestration.

use crate::section::{print_section, Section};
use crate::{checks, net, report, style};
use clap::Parser;
use std::io::IsTerminal;

#[derive(Parser)]
#[command(
    name = "vantage",
    version,
    about = "Web security scanner",
    override_usage = "vantage <domain> [--flags]",
    // Running `vantage` with no arguments at all prints help instead of scanning.
    arg_required_else_help = true,
    after_help = "With no module flags, runs the default HTTP audit (headers, cookies, cors, disclosure, csp, hsts, caching)."
)]
struct Args {
    /// domain or URL to scan (scheme optional; defaults to https). Optional if --targets is given.
    domain: Option<String>,

    /// run every check
    #[arg(long)]
    all: bool,
    /// DNS records (A/AAAA/NS/MX/TXT/SOA/CNAME)
    #[arg(long)]
    dnsrecon: bool,
    /// nmap service scan of common web ports
    #[arg(long)]
    nmap: bool,
    /// nmap -sV --script vulners (CVE matching)
    #[arg(long)]
    vulners: bool,
    /// full header dump + security-header matrix
    #[arg(long)]
    headers: bool,
    /// allowed HTTP methods (OPTIONS + probe)
    #[arg(long)]
    methods: bool,
    /// Content-Security-Policy analysis
    #[arg(long)]
    csp: bool,
    /// Strict-Transport-Security analysis
    #[arg(long)]
    hsts: bool,
    /// cookie flags (Secure/HttpOnly/SameSite)
    #[arg(long)]
    cookies: bool,
    /// CORS configuration
    #[arg(long)]
    cors: bool,
    /// server/framework header disclosure
    #[arg(long)]
    disclosure: bool,
    /// caching headers (shared-cache exposure of authenticated responses)
    #[arg(long)]
    caching: bool,
    /// compare authenticated vs unauthenticated response to confirm auth is enforced
    #[arg(long = "auth-check")]
    auth_check: bool,

    /// port spec for --nmap/--vulners (nmap -p syntax, e.g. "80,443" or "1-1024"); default is nmap's normal set
    #[arg(long, value_name = "SPEC")]
    ports: Option<String>,
    /// scan all 65535 ports with --nmap/--vulners (nmap -p-)
    #[arg(long = "all-ports")]
    all_ports: bool,

    /// scan every host listed in FILE (one per line; blank lines and # comments ignored)
    #[arg(long, value_name = "FILE")]
    targets: Option<String>,
    /// write a report to FILE; format inferred from extension (.md or .html)
    #[arg(long, value_name = "FILE")]
    report: Option<String>,

    /// send a custom request header (repeatable): --header "Name: Value"
    #[arg(long = "header", value_name = "H")]
    header: Vec<String>,
    /// send a cookie (repeatable): --cookie "name=value"
    #[arg(long = "cookie", value_name = "C")]
    cookie: Vec<String>,
    /// Authorization: Bearer <token>
    #[arg(long, value_name = "TOKEN")]
    bearer: Option<String>,
    /// Authorization: Basic, built from user:pass
    #[arg(long, value_name = "USER:PASS")]
    basic: Option<String>,
    /// override the User-Agent header
    #[arg(long = "user-agent", value_name = "UA")]
    user_agent: Option<String>,

    /// with --methods, also probe POST/PUT/DELETE/PATCH
    #[arg(long)]
    active: bool,
    /// throttle HTTP requests to N/min (0 = unlimited)
    #[arg(long, default_value_t = 0)]
    rate: i64,
    /// per-request timeout (seconds)
    #[arg(long, default_value_t = 15.0)]
    timeout: f64,
    /// accept invalid/self-signed TLS certificates
    #[arg(long)]
    insecure: bool,
    /// emit machine-readable JSON
    #[arg(long)]
    json: bool,
    /// disable colored output
    #[arg(long = "no-color")]
    no_color: bool,
}

/// Which checks to run, resolved once and reused for every target.
struct Plan {
    dns: bool,
    nmap: bool,
    vulners: bool,
    headers: bool,
    cookies: bool,
    cors: bool,
    disclosure: bool,
    csp: bool,
    hsts: bool,
    caching: bool,
    auth_check: bool,
    methods: bool,
    active: bool,
    port_spec: Option<String>,
    auth_cookies: Vec<String>,
}

impl Plan {
    fn needs_fetch(&self) -> bool {
        self.headers
            || self.cookies
            || self.cors
            || self.disclosure
            || self.csp
            || self.hsts
            || self.caching
            || self.auth_check
    }
}

/// The outcome of scanning a single target.
struct TargetResult {
    url: String,
    host: String,
    status: Option<u16>,
    fetch_failed: bool,
    sections: Vec<Section>,
}

pub fn run() -> i32 {
    let args = Args::parse();
    style::set_color(!args.no_color && !args.json && std::io::stdout().is_terminal());

    let module_flags = [
        args.dnsrecon,
        args.nmap,
        args.vulners,
        args.headers,
        args.methods,
        args.csp,
        args.hsts,
        args.cookies,
        args.cors,
        args.disclosure,
        args.caching,
        args.auth_check,
    ];
    let selected = module_flags.iter().any(|&x| x);
    let default_http = !selected && !args.all;
    let on = |flag: bool| args.all || flag;

    // Explicit --ports wins; otherwise --all-ports means nmap -p-; otherwise
    // no -p flag at all, so nmap scans its normal default port set.
    let port_spec: Option<String> = if let Some(p) = &args.ports {
        Some(p.clone())
    } else if args.all_ports {
        Some("-".to_string())
    } else {
        None
    };

    let plan = Plan {
        dns: on(args.dnsrecon),
        nmap: on(args.nmap),
        vulners: on(args.vulners),
        headers: args.all || args.headers || default_http,
        cookies: args.all || args.cookies || default_http,
        cors: args.all || args.cors || default_http,
        disclosure: args.all || args.disclosure || default_http,
        csp: args.all || args.csp || default_http,
        hsts: args.all || args.hsts || default_http,
        caching: args.all || args.caching || default_http,
        auth_check: on(args.auth_check),
        methods: on(args.methods),
        active: args.active,
        port_spec,
        auth_cookies: cookie_names(&args.cookie),
    };

    let headers = match net::build_headers(
        args.user_agent.as_deref(),
        &args.header,
        &args.cookie,
        args.bearer.as_deref(),
        args.basic.as_deref(),
    ) {
        Ok(h) => h,
        Err(e) => {
            if args.json {
                println!("{}", serde_json::json!({ "error": e }));
            } else {
                eprintln!("{}", style::red(&format!("error: {e}")));
            }
            return 2;
        }
    };
    let cfg = net::HttpConfig {
        timeout: args.timeout,
        insecure: args.insecure,
        headers,
    };

    let authenticated = args.user_agent.is_some()
        || !args.header.is_empty()
        || !args.cookie.is_empty()
        || args.bearer.is_some()
        || args.basic.is_some();

    // Resolve the target list: the positional domain plus any --targets file.
    let mut targets: Vec<String> = Vec::new();
    if let Some(d) = &args.domain {
        targets.push(d.clone());
    }
    if let Some(file) = &args.targets {
        match std::fs::read_to_string(file) {
            Ok(txt) => {
                for line in txt.lines() {
                    let t = line.trim();
                    if !t.is_empty() && !t.starts_with('#') {
                        targets.push(t.to_string());
                    }
                }
            }
            Err(e) => {
                eprintln!("{}", style::red(&format!("cannot read --targets {file}: {e}")));
                return 2;
            }
        }
    }
    if targets.is_empty() {
        eprintln!(
            "{}",
            style::red("provide a domain to scan, or a list via --targets <file>")
        );
        return 2;
    }

    let mut rate = net::RateLimiter::new(args.rate);
    let multi = targets.len() > 1;

    if !args.json {
        println!("{}", style::dim("vantage - web security scanner"));
        if authenticated {
            println!(
                "{} {}",
                style::bold("Authenticated:"),
                style::dim(&auth_summary(&args))
            );
        }
    }

    let mut results: Vec<TargetResult> = Vec::new();
    for target in &targets {
        let url = net::normalize_url(target);
        if !args.json {
            if multi {
                println!("\n{}", style::bold(&"#".repeat(64)));
            }
            println!("{} {}", style::bold("Target:"), url);
            if authenticated && url.starts_with("http://") {
                println!(
                    "{}",
                    style::red("  warning: sending credentials over plaintext http://")
                );
            }
        }

        let result = scan_one(&url, &plan, &cfg, &mut rate, authenticated, args.json);
        if !args.json {
            for sec in &result.sections {
                print_section(sec);
            }
        }
        results.push(result);
    }

    if let Some(path) = &args.report {
        write_report(path, &results);
    }

    if args.json {
        emit_json(&results);
    } else {
        println!();
    }

    // Preserve the original single-target contract: a failed fetch exits 2.
    if results.len() == 1 && results[0].fetch_failed {
        2
    } else {
        0
    }
}

/// Pull the cookie names out of the --cookie values (each may hold several
/// "name=value" pairs separated by ';').
fn cookie_names(cookies: &[String]) -> Vec<String> {
    let mut names = Vec::new();
    for c in cookies {
        for pair in c.split(';') {
            let name = pair.split('=').next().unwrap_or("").trim();
            if !name.is_empty() {
                names.push(name.to_string());
            }
        }
    }
    names
}

/// A one-line summary of the supplied credentials, for the banner.
fn auth_summary(args: &Args) -> String {
    let mut bits = Vec::new();
    if !args.header.is_empty() {
        bits.push(format!("{} header(s)", args.header.len()));
    }
    if !args.cookie.is_empty() {
        bits.push(format!("{} cookie(s)", args.cookie.len()));
    }
    if args.bearer.is_some() {
        bits.push("bearer token".into());
    }
    if args.basic.is_some() {
        bits.push("basic auth".into());
    }
    if args.user_agent.is_some() {
        bits.push("custom UA".into());
    }
    bits.join(", ")
}

fn scan_one(
    url: &str,
    plan: &Plan,
    cfg: &net::HttpConfig,
    rate: &mut net::RateLimiter,
    authenticated: bool,
    json: bool,
) -> TargetResult {
    let host = net::host_of(url);
    let mut sections: Vec<Section> = Vec::new();
    let mut status = None;
    let mut fetch_failed = false;

    if plan.dns {
        sections.push(checks::dnsrecon(&host));
    }
    if plan.vulners {
        sections.push(checks::nmap(&host, true, plan.port_spec.as_deref()));
    } else if plan.nmap {
        sections.push(checks::nmap(&host, false, plan.port_spec.as_deref()));
    }

    if plan.needs_fetch() {
        match net::fetch(url, cfg, rate) {
            Ok(f) => {
                status = Some(f.status);
                if !json {
                    let mut line = format!("HTTP {}", f.status);
                    if f.redirected {
                        line += &format!("  (redirected to {})", f.url);
                    }
                    println!("{}", style::dim(&line));
                    // Cross-host redirect guard: reqwest drops Authorization on a
                    // cross-origin redirect but not cookies/custom headers, so
                    // credentials can still reach an unexpected host.
                    if authenticated && f.redirected {
                        let to = net::host_of(&f.url);
                        if !host.eq_ignore_ascii_case(&to) {
                            println!(
                                "{}",
                                style::red(&format!(
                                    "  warning: redirected to a different host ({to}); cookies/custom headers may have been sent there"
                                ))
                            );
                        }
                    }
                }
                if plan.headers {
                    sections.push(checks::headers(&f));
                }
                if plan.cookies {
                    sections.push(checks::cookies(&f, &plan.auth_cookies));
                }
                if plan.cors {
                    sections.push(checks::cors(&f));
                }
                if plan.disclosure {
                    sections.push(checks::disclosure(&f));
                }
                if plan.csp {
                    sections.push(checks::csp(&f));
                }
                if plan.hsts {
                    sections.push(checks::hsts(&f));
                }
                if plan.caching {
                    sections.push(checks::caching(&f, authenticated));
                }
                if plan.auth_check {
                    if authenticated {
                        sections.push(checks::auth_effect(url, &f, cfg, rate));
                    } else {
                        let mut sec = Section::new("Auth effectiveness");
                        sec.note("no credentials supplied; nothing to compare (see --cookie/--bearer/--header)");
                        sections.push(sec);
                    }
                }
            }
            Err(e) => {
                fetch_failed = true;
                if !json {
                    println!("{}", style::red(&format!("fetch failed: {e}")));
                }
                let mut sec = Section::new("HTTP");
                sec.bad(&format!("fetch failed: {e}"));
                sections.push(sec);
            }
        }
    }

    if plan.methods {
        sections.push(checks::methods(url, plan.active, cfg, rate));
    }

    TargetResult {
        url: url.to_string(),
        host,
        status,
        fetch_failed,
        sections,
    }
}

fn emit_json(results: &[TargetResult]) {
    let one = |r: &TargetResult| {
        serde_json::json!({
            "target": r.url,
            "host": r.host,
            "status": r.status,
            "sections": r.sections.iter().map(|sec| serde_json::json!({
                "title": sec.title,
                "lines": sec.lines,
            })).collect::<Vec<_>>(),
        })
    };
    let out = if results.len() == 1 {
        one(&results[0])
    } else {
        serde_json::json!({ "targets": results.iter().map(one).collect::<Vec<_>>() })
    };
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}

fn write_report(path: &str, results: &[TargetResult]) {
    let reports: Vec<report::TargetReport> = results
        .iter()
        .map(|r| report::TargetReport {
            target: &r.url,
            host: &r.host,
            status: r.status,
            sections: &r.sections,
        })
        .collect();
    let fmt = report::Format::from_path(path);
    let content = report::render(&fmt, &reports);
    // Written to stderr so it never pollutes --json / piped stdout.
    match std::fs::write(path, content) {
        Ok(_) => eprintln!("{}", style::dim(&format!("report written to {path}"))),
        Err(e) => eprintln!("{}", style::red(&format!("failed to write report {path}: {e}"))),
    }
}
