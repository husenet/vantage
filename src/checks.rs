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
    ("cross-origin-opener-policy", "COOP - isolates the browsing context"),
    ("cross-origin-embedder-policy", "COEP - requires cross-origin resources to opt in"),
    ("cross-origin-resource-policy", "CORP - limits which sites can load the resource"),
];

/// Shortest HSTS max-age generally considered adequate (6 months).
const HSTS_MIN_AGE: i64 = 15_768_000;
/// Shortest max-age the HSTS preload list accepts (1 year).
const PRELOAD_MIN_AGE: i64 = 31_536_000;
/// Origin sent to see whether the server reflects arbitrary origins in CORS.
const PROBE_ORIGIN: &str = "https://vantage-cors-probe.example";

/// Cookie names that carry a session, login, or anti-CSRF value, where losing
/// same-site protection actually matters.
fn is_session_cookie(name: &str) -> bool {
    let n = name.to_lowercase();
    [
        "sess",
        "sid",
        "auth",
        "token",
        "jwt",
        "login",
        "remember",
        "csrf",
        "xsrf",
        "antiforgery",
        "aspnetcore.cookies",
        "applicationcookie",
    ]
    .iter()
    .any(|k| n.contains(k))
}

/// Cookie names that name the stack that issued them.
const FRAMEWORK_COOKIES: &[(&str, &str)] = &[
    ("asp.net_sessionid", "ASP.NET"),
    (".aspnetcore.", "ASP.NET Core"),
    (".aspnet.", "ASP.NET"),
    (".mvc.", "ASP.NET Core MVC"),
    ("arraffinity", "Azure App Service"),
    ("phpsessid", "PHP"),
    ("jsessionid", "Java"),
    ("laravel_session", "Laravel"),
    ("ci_session", "CodeIgniter"),
    ("connect.sid", "Express"),
    ("_rails_session", "Rails"),
    ("django", "Django"),
];

struct Hsts {
    max_age: Option<i64>,
    include_subdomains: bool,
    preload: bool,
    repeated_max_age: bool,
}

fn parse_hsts(v: &str) -> Hsts {
    let mut h = Hsts {
        max_age: None,
        include_subdomains: false,
        preload: false,
        repeated_max_age: false,
    };
    let mut seen = false;
    for part in v.split(';') {
        let p = part.trim().to_lowercase();
        if let Some(rest) = p.strip_prefix("max-age=") {
            if seen {
                h.repeated_max_age = true;
            }
            seen = true;
            h.max_age = rest.trim().trim_matches('"').parse::<i64>().ok();
        } else if p == "includesubdomains" {
            h.include_subdomains = true;
        } else if p == "preload" {
            h.preload = true;
        }
    }
    h
}

/// True when the CSP names frame-ancestors, which makes browsers ignore
/// X-Frame-Options entirely.
fn csp_has_frame_ancestors(f: &Fetched) -> bool {
    f.get("content-security-policy")
        .map(|p| {
            p.split(';')
                .any(|d| d.trim().split_whitespace().next().unwrap_or("") == "frame-ancestors")
        })
        .unwrap_or(false)
}

/// Judge whether a security header actually does anything. Returns Some(reason)
/// when the header is present but its value leaves the protection off.
fn header_ineffective(name: &str, value: &str, f: &Fetched) -> Option<String> {
    let v = value.trim();
    let low = v.to_lowercase();
    if v.is_empty() {
        return Some("empty value".into());
    }
    // A single token, ignoring any report-to/report-uri style parameters.
    let token = low.split(';').next().unwrap_or("").trim();
    match name {
        "strict-transport-security" => {
            if !f.is_https {
                return Some("served over http".into());
            }
            let h = parse_hsts(v);
            if h.repeated_max_age {
                return Some("repeated max-age".into());
            }
            match h.max_age {
                None => Some("no valid max-age".into()),
                Some(0) => Some("max-age=0".into()),
                _ => None,
            }
        }
        // Only DENY and SAMEORIGIN are honored; ALLOW-FROM was never implemented.
        "x-frame-options" => {
            if csp_has_frame_ancestors(f) {
                Some("overridden by CSP frame-ancestors".into())
            } else if low == "deny" || low == "sameorigin" {
                None
            } else {
                Some(format!("{v} is not honored"))
            }
        }
        "x-content-type-options" => {
            if low == "nosniff" {
                None
            } else {
                Some(format!("{v} is not nosniff"))
            }
        }
        "referrer-policy" => {
            if low.split(',').any(|t| t.trim() == "unsafe-url") {
                Some("unsafe-url sends the full URL".into())
            } else {
                None
            }
        }
        "cross-origin-opener-policy" | "cross-origin-embedder-policy" => {
            if token == "unsafe-none" {
                Some("unsafe-none is the default".into())
            } else {
                None
            }
        }
        "cross-origin-resource-policy" => {
            if low == "cross-origin" {
                Some("cross-origin allows any site".into())
            } else {
                None
            }
        }
        "permissions-policy" => {
            // An allowlist of * grants the feature to every embedded frame, so a
            // policy whose entries are all * is looser than sending no header.
            let mut any = false;
            let all_star = low
                .split(',')
                .filter(|d| !d.trim().is_empty())
                .all(|d| {
                    any = true;
                    d.split('=')
                        .nth(1)
                        .map(|a| a.trim().trim_matches('"') == "*")
                        .unwrap_or(false)
                });
            if any && all_star {
                Some("every feature allowlisted to *".into())
            } else {
                None
            }
        }
        _ => None,
    }
}

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
        // Cookies are shown in full; other long values are trimmed for readability.
        let vv = if k == "set-cookie" || v.chars().count() <= 100 {
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
        match f.get(name) {
            None => sec.bad(&format!("{name} ({desc})")),
            Some(v) => match header_ineffective(name, &v, f) {
                None => sec.good(name),
                Some(why) => sec.bad(&format!("{name} ineffective ({why})")),
            },
        }
    }
    sec
}

pub fn cookies(f: &Fetched, auth_cookies: &[String]) -> Section {
    let mut sec = Section::new("Cookies");
    let cks = f.get_all("set-cookie");
    let mut seen: Vec<String> = Vec::new();

    // Names of every cookie in this response, so a cookie can be judged against
    // its companions (see the SameSite pair below).
    let names: Vec<&str> = cks
        .iter()
        .map(|c| c.split('=').next().unwrap_or("").trim())
        .collect();

    for c in &cks {
        let name = c.split('=').next().unwrap_or("").trim();
        seen.push(name.to_string());
        let is_auth = auth_cookies.iter().any(|a| a.eq_ignore_ascii_case(name));
        // Attributes are only the ';'-separated pairs after the cookie value, so
        // parse them rather than substring-matching the whole line: a value or a
        // Domain like "secure.example.com" must not count as the Secure flag.
        let attrs: Vec<&str> = c.split(';').skip(1).map(str::trim).collect();
        let has = |n: &str| {
            attrs.iter().any(|a| {
                a.split('=').next().unwrap_or("").trim().eq_ignore_ascii_case(n)
            })
        };
        let same_site: Option<&str> = attrs.iter().find_map(|a| {
            let (k, v) = a.split_once('=')?;
            if k.trim().eq_ignore_ascii_case("samesite") {
                Some(v.trim())
            } else {
                None
            }
        });
        let secure = has("secure");
        let none_ss = same_site.map(|v| v.eq_ignore_ascii_case("none")).unwrap_or(false);

        let mut missing = Vec::new();
        if !secure {
            missing.push("Secure");
        }
        if !has("httponly") {
            missing.push("HttpOnly");
        }
        // A cookie with no SameSite that ships alongside a "<name>SameSite"
        // companion is the deliberate legacy half of a pair (Azure App Service
        // emits ARRAffinity + ARRAffinitySameSite this way), so the modern
        // companion already covers current browsers.
        let companion = format!("{name}SameSite");
        let paired = names.iter().any(|o| o.eq_ignore_ascii_case(&companion));
        if same_site.is_none() && !paired {
            missing.push("SameSite");
        }

        // Show the full Set-Cookie line, then the flag verdict for it.
        sec.text(format!("  {}", s::dim(c)));
        let label = if is_auth {
            format!("{name} (auth cookie)")
        } else {
            name.to_string()
        };
        if none_ss && !secure {
            // Browsers refuse to store SameSite=None without Secure.
            sec.bad(&format!(
                "{label} - ineffective (SameSite=None without Secure, cookie not stored)"
            ));
        } else if !missing.is_empty() {
            sec.bad(&format!("{label} - missing {}", missing.join(", ")));
        } else if !f.is_https {
            sec.bad(&format!(
                "{label} - Secure ineffective (response served over http)"
            ));
        } else if none_ss && (is_auth || is_session_cookie(name)) {
            // SameSite=None is a deliberate, valid choice for a cookie that has
            // to travel cross-site, so it is only a weakness on a session or
            // auth cookie, where it removes the CSRF protection.
            sec.bad(&format!(
                "{label} - SameSite=None on a session cookie (sent on cross-site requests)"
            ));
        } else {
            let ss = match same_site {
                Some(v) => format!("SameSite={v}"),
                None => "SameSite via companion cookie".to_string(),
            };
            sec.good(&format!("{label} - Secure, HttpOnly, {ss} set"));
        }
    }

    // Auth cookies we sent but the server did not re-issue: their flags are set
    // by the server on Set-Cookie, so a plain request cookie carries none to check.
    for a in auth_cookies {
        if !seen.iter().any(|n| n.eq_ignore_ascii_case(a)) {
            sec.note(&format!(
                "{a} (auth cookie) not re-issued; flags not visible on this response"
            ));
        }
    }

    if cks.is_empty() && auth_cookies.is_empty() {
        sec.good("no Set-Cookie headers");
    }
    sec
}

pub fn cors(f: &Fetched, cfg: &net::HttpConfig, rate: &mut RateLimiter) -> Section {
    let mut sec = Section::new("CORS");

    // Servers that reflect the request Origin send no ACAO when no Origin was
    // sent, so the first response alone cannot tell "restricted" from
    // "reflects anything". Ask again with an Origin to find out.
    let probe = net::fetch(&f.url, &net::with_origin(cfg, PROBE_ORIGIN), rate).ok();
    let probe_acao = probe.as_ref().and_then(|p| p.get("access-control-allow-origin"));
    let creds = [
        f.get("access-control-allow-credentials"),
        probe.as_ref().and_then(|p| p.get("access-control-allow-credentials")),
    ]
    .iter()
    .flatten()
    .any(|v| v.trim().eq_ignore_ascii_case("true"));

    let acao = match f
        .get("access-control-allow-origin")
        .or_else(|| probe_acao.clone())
    {
        None => {
            sec.good("no cross-origin sharing (same-origin only)");
            return sec;
        }
        Some(v) => v,
    };
    sec.text(format!("  access-control-allow-origin: {}", s::dim(&acao)));

    let a = acao.trim();
    if probe_acao.as_deref().map(str::trim) == Some(PROBE_ORIGIN) {
        if creds {
            sec.bad("reflects any origin with credentials");
        } else {
            sec.bad("reflects any origin");
        }
    } else if a == "*" {
        if creds {
            sec.bad("wildcard origin (*) with credentials");
        } else {
            sec.bad("wildcard origin (*)");
        }
    } else if a.eq_ignore_ascii_case("null") {
        sec.bad("origin null ineffective (any sandboxed iframe or data: document sends it)");
    } else if f.is_https && a.to_lowercase().starts_with("http://") {
        sec.bad(&format!("allows an http origin ({a})"));
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
            sec.bad(&format!("{}: {}", s::magenta(name), s::dim(&v)));
        }
    }

    // Cookies leak too: a Domain attribute can name the backend origin behind a
    // proxy or custom domain, and the cookie name often names the stack. Collect
    // the distinct facts rather than repeating one per cookie.
    let host = net::host_of(&f.url);
    let mut backends: Vec<String> = Vec::new();
    let mut stacks: Vec<&str> = Vec::new();
    for c in f.get_all("set-cookie") {
        let name = c.split('=').next().unwrap_or("").trim().to_lowercase();
        let attrs: Vec<&str> = c.split(';').skip(1).map(str::trim).collect();
        if let Some(domain) = attrs.iter().find_map(|a| {
            let (k, v) = a.split_once('=')?;
            if k.trim().eq_ignore_ascii_case("domain") {
                Some(v.trim().trim_start_matches('.'))
            } else {
                None
            }
        }) {
            // Only a domain outside the scanned host is a leak; a parent of the
            // host (example.com for app.example.com) is ordinary scoping.
            let same = host.eq_ignore_ascii_case(domain)
                || host
                    .to_lowercase()
                    .ends_with(&format!(".{}", domain.to_lowercase()));
            if !same && !backends.iter().any(|h| h.eq_ignore_ascii_case(domain)) {
                backends.push(domain.to_string());
            }
        }
        if let Some((_, stack)) = FRAMEWORK_COOKIES.iter().find(|(k, _)| name.contains(k)) {
            if !stacks.contains(stack) {
                stacks.push(stack);
            }
        }
    }
    for b in &backends {
        any = true;
        sec.bad(&format!("backend host in cookie Domain: {}", s::dim(b)));
    }
    if !stacks.is_empty() {
        any = true;
        stacks.sort_unstable();
        sec.bad(&format!("cookie names reveal {}", stacks.join(", ")));
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
                sec.bad("only Content-Security-Policy-Report-Only set");
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
        // frame-ancestors does not end in -src but controls framing, and it
        // overrides X-Frame-Options, so its value matters just as much.
        if !(name.ends_with("-src") || name == "default-src" || name == "frame-ancestors") {
            continue;
        }
        for v in vals {
            match v.as_str() {
                "'unsafe-inline'" => sec.bad(&format!("{name} allows 'unsafe-inline'")),
                "'unsafe-eval'" => sec.bad(&format!("{name} allows 'unsafe-eval'")),
                "*" => sec.bad(&format!("{name} allows wildcard *")),
                "http:" => sec.bad(&format!("{name} allows http: sources")),
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

    // Browsers discard the whole header when it does not arrive over https or
    // when the host is an IP literal, so nothing below it would be applied.
    if !f.is_https {
        sec.bad("ineffective (served over http)");
        return sec;
    }
    if net::host_of(&f.url)
        .trim_matches(|c| c == '[' || c == ']')
        .parse::<std::net::IpAddr>()
        .is_ok()
    {
        sec.bad("ineffective (host is an IP address)");
        return sec;
    }

    let h = parse_hsts(&v);
    // A repeated or invalid max-age makes the field non-conforming, and max-age=0
    // deletes the stored policy, so the other directives never take effect.
    if h.repeated_max_age {
        sec.bad("ineffective (repeated max-age)");
        return sec;
    }
    match h.max_age {
        None => {
            sec.bad("ineffective (no valid max-age)");
            return sec;
        }
        Some(0) => {
            sec.bad("ineffective (max-age=0 deletes the policy)");
            return sec;
        }
        Some(ma) if ma < HSTS_MIN_AGE => {
            sec.bad(&format!("max-age too short: {ma} (~{}d)", ma / 86400))
        }
        Some(ma) => sec.good(&format!("max-age={ma} (~{}d)", ma / 86400)),
    }
    if h.include_subdomains {
        sec.good("includeSubDomains set");
    } else {
        sec.bad("includeSubDomains not set");
    }
    // The preload list requires max-age >= 1 year plus includeSubDomains, so the
    // token alone is inert if either is missing.
    if h.preload {
        let mut unmet = Vec::new();
        if h.max_age.map_or(true, |ma| ma < PRELOAD_MIN_AGE) {
            unmet.push("max-age under 1y");
        }
        if !h.include_subdomains {
            unmet.push("no includeSubDomains");
        }
        if unmet.is_empty() {
            sec.good("preload set");
        } else {
            sec.bad(&format!("preload ineffective ({})", unmet.join(", ")));
        }
    }
    sec
}

pub fn caching(f: &Fetched, authenticated: bool) -> Section {
    let mut sec = Section::new("Caching");
    let cc = f.get("cache-control");
    for name in ["cache-control", "pragma", "expires", "age", "vary"] {
        if let Some(v) = f.get(name) {
            sec.text(format!("  {}: {}", s::magenta(name), s::dim(&v)));
        }
    }

    // Only an authenticated response is a confidentiality concern: if it can be
    // stored by a shared cache, private data may leak to other users.
    if authenticated {
        let low = cc.as_deref().unwrap_or("").to_lowercase();
        if cc.is_none() {
            sec.bad("no Cache-Control on an authenticated response");
        } else if low.contains("public") {
            sec.bad("authenticated response marked Cache-Control: public");
        } else if low.contains("no-store") {
            sec.good("no-store set");
        } else if low.contains("private") {
            // private only bars shared caches; the browser still stores it.
            sec.good("private set, not stored by shared caches");
        } else {
            sec.bad("authenticated response is cacheable (no no-store / private)");
        }
        // A non-zero Age is a shared cache reporting that it stored and replayed
        // this response, whatever the directives now say.
        if let Some(age) = f.get("age").and_then(|v| v.trim().parse::<i64>().ok()) {
            if age > 0 {
                sec.bad(&format!("served from a shared cache (age {age})"));
            }
        }
    }
    sec
}

/// Compare the authenticated response against an unauthenticated one to confirm
/// the session is actually being enforced. Only meaningful when credentials
/// were supplied; `authed` is the response already fetched with them.
pub fn auth_effect(
    url: &str,
    authed: &Fetched,
    cfg: &net::HttpConfig,
    rate: &mut RateLimiter,
) -> Section {
    let mut sec = Section::new("Auth effectiveness");

    // Re-fetch with a UA-only config (no cookies / tokens / custom headers).
    let bare = net::build_headers(None, &[], &[], None, None)
        .expect("static User-Agent header is always valid");
    let anon_cfg = net::HttpConfig {
        timeout: cfg.timeout,
        insecure: cfg.insecure,
        headers: bare,
    };
    let anon = match net::fetch(url, &anon_cfg, rate) {
        Ok(a) => a,
        Err(e) => {
            sec.note(&format!("could not fetch unauthenticated baseline: {e}"));
            return sec;
        }
    };

    sec.text(format!(
        "  authenticated: HTTP {} ({} bytes)",
        authed.status, authed.body_len
    ));
    sec.text(format!(
        "  unauthenticated: HTTP {} ({} bytes)",
        anon.status, anon.body_len
    ));

    let anon_blocked = matches!(anon.status, 401 | 403) || (anon.status >= 300 && anon.status < 400);
    let authed_ok = authed.status >= 200 && authed.status < 300;
    // Treat responses within 5% (or 64 bytes) of each other as "the same page".
    let diff = authed.body_len.abs_diff(anon.body_len);
    let similar = diff <= 64 || diff * 20 <= authed.body_len.max(1);

    if anon_blocked && authed_ok {
        sec.good(&format!(
            "auth enforced: unauthenticated request returns {}, authenticated returns {}",
            anon.status, authed.status
        ));
    } else if authed.status == anon.status && similar {
        sec.bad("same response with and without credentials");
    } else {
        sec.note("inconclusive: authenticated and unauthenticated responses differ");
    }
    sec
}

pub fn methods(url: &str, active: bool, cfg: &net::HttpConfig, rate: &mut RateLimiter) -> Section {
    let mut sec = Section::new("HTTP methods");

    let mut probe = vec!["GET", "HEAD", "OPTIONS", "TRACE"];
    if active {
        probe.extend(["POST", "PUT", "DELETE", "PATCH"]);
    }
    for m in probe {
        let code = net::request(m, url, cfg, rate)
            .map(|r| r.status().as_u16())
            .unwrap_or(0);
        // "allowed" = the method returned a success/redirect (2xx/3xx); anything
        // else (400/401/403/404/405/501/dropped) is "blocked". The status code is
        // shown so the raw signal is never hidden.
        let mark = if matches!(code, 200..=399) {
            s::green("allowed")
        } else {
            s::dim("blocked")
        };
        sec.text(format!("  {}  {:>3}  {}", mark, code, s::bold(m)));
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
                sec.note("nslookup not found on PATH (e.g. sudo apt install dnsutils)");
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

/// Run an nmap `-sV` scan (optionally with the vulners CVE script).
///
/// `ports` follows nmap `-p` syntax (e.g. "80,443" or "1-1024", or "-" for all
/// 65535). When it is `None`, no `-p` flag is passed and nmap scans its normal
/// default set (top ~1000 ports).
pub fn nmap(host: &str, vulners: bool, ports: Option<&str>) -> Section {
    let title = format!(
        "{} ({host})",
        if vulners {
            "nmap --script vulners"
        } else {
            "nmap service scan"
        }
    );
    let mut sec = Section::new(title);

    let mut args: Vec<String> = vec!["-Pn".into(), "-sV".into()];
    if let Some(p) = ports {
        args.push("-p".into());
        args.push(p.into());
    }
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
            sec.note("nmap not installed / not on PATH (e.g. sudo apt install nmap)");
            return sec;
        }
        Err(e) => {
            sec.note(&format!("nmap failed to launch: {e}"));
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
            sec.note(&format!("nmap exited with status {code}"));
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
            sec.bad(&format!("{cves} CVE line(s) reported by vulners"));
        } else {
            sec.good("no CVEs reported for the detected service versions");
        }
    }
    sec
}
