//! Command-line interface: flag parsing and check orchestration.

use crate::section::{print_section, Section};
use crate::{checks, net, style};
use clap::Parser;
use std::io::IsTerminal;

#[derive(Parser)]
#[command(
    name = "vantage",
    version,
    about = "Web security scanner - for authorized testing only.",
    override_usage = "vantage <domain> [--flags]",
    after_help = "With no module flags, runs the default HTTP audit (headers, cookies, cors, disclosure, csp, hsts)."
)]
struct Args {
    /// domain or URL to scan (scheme optional; defaults to https)
    domain: String,

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
    ];
    let selected = module_flags.iter().any(|&x| x);
    let default_http = !selected && !args.all;
    let on = |flag: bool| args.all || flag;

    let run_dns = on(args.dnsrecon);
    let run_nmap = on(args.nmap);
    let run_vulners = on(args.vulners);
    let run_headers = args.all || args.headers || default_http;
    let run_cookies = args.all || args.cookies || default_http;
    let run_cors = args.all || args.cors || default_http;
    let run_disclosure = args.all || args.disclosure || default_http;
    let run_csp = args.all || args.csp || default_http;
    let run_hsts = args.all || args.hsts || default_http;
    let run_methods = on(args.methods);

    let url = net::normalize_url(&args.domain);
    let host = net::host_of(&args.domain);
    let mut rate = net::RateLimiter::new(args.rate);

    if !args.json {
        println!("{}", style::dim("vantage - web security scanner"));
        println!(
            "{}",
            style::dim("Use only against systems you own or are authorized to test.")
        );
        println!("{} {}", style::bold("Target:"), url);
    }

    let mut sections: Vec<Section> = Vec::new();

    if run_dns {
        sections.push(checks::dnsrecon(&host));
    }
    if run_vulners {
        sections.push(checks::nmap(&host, true));
    } else if run_nmap {
        sections.push(checks::nmap(&host, false));
    }

    if run_headers || run_cookies || run_cors || run_disclosure || run_csp || run_hsts {
        match net::fetch(&url, args.timeout, args.insecure, &mut rate) {
            Ok(f) => {
                if !args.json {
                    let mut line = format!("HTTP {}", f.status);
                    if f.redirected {
                        line += &format!("  (redirected to {})", f.url);
                    }
                    println!("{}", style::dim(&line));
                }
                if run_headers {
                    sections.push(checks::headers(&f));
                }
                if run_cookies {
                    sections.push(checks::cookies(&f));
                }
                if run_cors {
                    sections.push(checks::cors(&f));
                }
                if run_disclosure {
                    sections.push(checks::disclosure(&f));
                }
                if run_csp {
                    sections.push(checks::csp(&f));
                }
                if run_hsts {
                    sections.push(checks::hsts(&f));
                }
            }
            Err(e) => {
                if args.json {
                    println!("{}", serde_json::json!({ "error": e.to_string() }));
                    return 2;
                }
                println!("{}", style::red(&format!("fetch failed: {e}")));
            }
        }
    }

    if run_methods {
        sections.push(checks::methods(
            &url,
            args.active,
            args.timeout,
            args.insecure,
            &mut rate,
        ));
    }

    if args.json {
        let out = serde_json::json!({
            "target": url,
            "host": host,
            "sections": sections.iter().map(|sec| serde_json::json!({
                "title": sec.title,
                "lines": sec.lines,
            })).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        return 0;
    }

    for sec in &sections {
        print_section(sec);
    }
    println!();
    0
}
