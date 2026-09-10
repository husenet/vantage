//! HTTP fetch helpers, URL normalization, and a request-rate limiter.

use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, COOKIE};
use reqwest::Method;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::thread;
use std::time::{Duration, Instant};

pub const USER_AGENT: &str = "vantage/0.9 (+https://github.com/husenet/vantage)";

/// Protocols and APIs identifiable from response headers alone. Naming one
/// matters because several of them reject any request that omits their protocol
/// header before ever weighing the method, which otherwise reads as a method
/// restriction. Each entry is (name, headers that identify it).
pub const PROTOCOLS: &[(&str, &[&str])] = &[
    (
        "tus resumable upload",
        &["tus-resumable", "tus-version", "tus-extension", "tus-max-size"],
    ),
    ("WebDAV", &["dav", "ms-author-via"]),
    ("OData", &["odata-version", "dataserviceversion"]),
    ("gRPC", &["grpc-status", "grpc-encoding", "grpc-accept-encoding"]),
    (
        "S3-compatible object storage",
        &["x-amz-request-id", "x-amz-id-2", "x-amz-bucket-region"],
    ),
    ("Azure Storage", &["x-ms-request-id", "x-ms-version"]),
    (
        "Elasticsearch / OpenSearch",
        &["x-elastic-product", "x-opensearch-version"],
    ),
    ("CouchDB", &["x-couchdb-body-time", "x-couch-request-id"]),
    (
        "WebSocket upgrade",
        &["sec-websocket-version", "sec-websocket-accept"],
    ),
    ("Kubernetes API", &["x-kubernetes-pf-flowschema-uid"]),
    ("HashiCorp Vault", &["x-vault-index", "x-vault-token"]),
];

/// Find the protocol a response advertises, as ("name", "header: value").
pub fn protocol_of(get: impl Fn(&str) -> Option<String>) -> Option<(String, String)> {
    PROTOCOLS.iter().find_map(|(name, headers)| {
        headers.iter().find_map(|h| {
            get(h).map(|v| ((*name).to_string(), format!("{h}: {}", v.trim())))
        })
    })
}

/// Shared request settings: timeout, TLS strictness, and the default headers
/// (User-Agent plus any auth the user passed).
pub struct HttpConfig {
    pub timeout: f64,
    pub insecure: bool,
    pub headers: HeaderMap,
    /// Force HTTP/1.1 instead of letting ALPN negotiate HTTP/2.
    pub http1_only: bool,
}

/// Build the default-header map from the CLI auth inputs. Returns a
/// human-readable error describing the first malformed input, if any.
///
/// Precedence for the Authorization header: an explicit `--header
/// "Authorization: ..."` is overridden by `--bearer`/`--basic` if those are
/// also given (bearer wins over basic).
pub fn build_headers(
    user_agent: Option<&str>,
    headers: &[String],
    cookies: &[String],
    bearer: Option<&str>,
    basic: Option<&str>,
) -> Result<HeaderMap, String> {
    let mut map = HeaderMap::new();

    let ua = user_agent.unwrap_or(USER_AGENT);
    map.insert(
        reqwest::header::USER_AGENT,
        HeaderValue::from_str(ua).map_err(|_| format!("invalid --user-agent value: {ua}"))?,
    );

    // Arbitrary "Name: Value" headers (repeatable). Same-named headers stack.
    for h in headers {
        let (name, value) = h
            .split_once(':')
            .ok_or_else(|| format!("invalid --header (expected 'Name: Value'): {h}"))?;
        let name = name.trim();
        let value = value.trim();
        let hname = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| format!("invalid header name: {name}"))?;
        let hval =
            HeaderValue::from_str(value).map_err(|_| format!("invalid header value for {name}"))?;
        map.append(hname, hval);
    }

    // Cookies (repeatable) collapse into one Cookie header, as a browser sends.
    if !cookies.is_empty() {
        let joined = cookies
            .iter()
            .map(|c| strip_cookie_prefix(c))
            .collect::<Vec<_>>()
            .join("; ");
        map.insert(
            COOKIE,
            HeaderValue::from_str(&joined).map_err(|_| "invalid --cookie value".to_string())?,
        );
    }

    // Bearer / Basic convenience shortcuts for the Authorization header.
    if let Some(tok) = bearer {
        let v = format!("Bearer {tok}");
        map.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&v).map_err(|_| "invalid --bearer token".to_string())?,
        );
    } else if let Some(creds) = basic {
        let v = format!("Basic {}", base64_encode(creds.as_bytes()));
        map.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&v).map_err(|_| "invalid --basic value".to_string())?,
        );
    }

    Ok(map)
}

/// Standard base64 with padding, for `--basic user:pass`.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Clone the config with an Origin header added, for the CORS reflection probe.
pub fn with_origin(cfg: &HttpConfig, origin: &str) -> HttpConfig {
    let mut headers = cfg.headers.clone();
    if let Ok(v) = HeaderValue::from_str(origin) {
        headers.insert(reqwest::header::ORIGIN, v);
    }
    HttpConfig {
        timeout: cfg.timeout,
        insecure: cfg.insecure,
        headers,
        http1_only: cfg.http1_only,
    }
}

/// A pasted cookie string often includes the leading "Cookie:" header name
/// (e.g. copied from devtools). Drop it so the value is just the pairs.
pub fn strip_cookie_prefix(s: &str) -> &str {
    let t = s.trim();
    match t.get(..7) {
        Some(p) if p.eq_ignore_ascii_case("cookie:") => t[7..].trim(),
        _ => t,
    }
}

/// True when a positional argument cannot be a host/URL and is almost certainly
/// a mis-pasted cookie or header (contains whitespace, or the host part carries
/// a '='). Used to catch `vantage --cookies "a=b; c=d"` style mistakes.
pub fn looks_like_pasted_value(target: &str) -> bool {
    let t = target.trim();
    if t.is_empty() || t.chars().any(|c| c.is_whitespace()) {
        return true;
    }
    let host = host_of(t);
    host.is_empty() || host.contains('=')
}

pub fn normalize_url(target: &str) -> String {
    let t = target.trim();
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{t}")
    }
}

pub fn host_of(target: &str) -> String {
    let u = normalize_url(target);
    reqwest::Url::parse(&u)
        .ok()
        .and_then(|p| p.host_str().map(|h| h.to_string()))
        .unwrap_or_else(|| target.trim().to_string())
}

/// Throttle to N requests per minute (0 = unlimited).
pub struct RateLimiter {
    interval: Duration,
    last: Option<Instant>,
}

impl RateLimiter {
    pub fn new(rpm: i64) -> Self {
        let interval = if rpm > 0 {
            Duration::from_secs_f64(60.0 / rpm as f64)
        } else {
            Duration::ZERO
        };
        RateLimiter {
            interval,
            last: None,
        }
    }

    pub fn wait(&mut self) {
        if self.interval.is_zero() {
            return;
        }
        if let Some(last) = self.last {
            let delta = last.elapsed();
            if delta < self.interval {
                thread::sleep(self.interval - delta);
            }
        }
        self.last = Some(Instant::now());
    }
}

pub struct Fetched {
    pub status: u16,
    pub url: String,
    pub headers: HeaderMap,
    pub is_https: bool,
    /// True only if the final URL differs from the request after URL
    /// normalization (so a bare host gaining a trailing "/" does not count).
    pub redirected: bool,
    /// Length of the decoded response body, used to compare authenticated vs
    /// unauthenticated responses in the auth-effectiveness check.
    pub body_len: usize,
    /// Negotiated protocol ("HTTP/1.1", "HTTP/2"). Reported because the header
    /// count depends on it: hop-by-hop headers exist in 1.1 but not 2.
    pub version: String,
}

impl Fetched {
    pub fn get(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    pub fn get_all(&self, name: &str) -> Vec<String> {
        self.headers
            .get_all(name)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .collect()
    }
}

fn client(cfg: &HttpConfig, follow: bool) -> reqwest::Result<Client> {
    let mut b = Client::builder()
        .danger_accept_invalid_certs(cfg.insecure)
        .timeout(Duration::from_secs_f64(cfg.timeout))
        .default_headers(cfg.headers.clone());
    if !follow {
        b = b.redirect(reqwest::redirect::Policy::none());
    }
    if cfg.http1_only {
        b = b.http1_only();
    }
    b.build()
}

/// Human name for the negotiated protocol, so a header count in a report can be
/// reproduced (hop-by-hop headers exist in HTTP/1.1 but not HTTP/2).
pub fn version_str(v: reqwest::Version) -> &'static str {
    match v {
        reqwest::Version::HTTP_09 => "HTTP/0.9",
        reqwest::Version::HTTP_10 => "HTTP/1.0",
        reqwest::Version::HTTP_11 => "HTTP/1.1",
        reqwest::Version::HTTP_2 => "HTTP/2",
        reqwest::Version::HTTP_3 => "HTTP/3",
        _ => "HTTP",
    }
}

fn hash_bytes(b: &[u8]) -> u64 {
    let mut h = DefaultHasher::new();
    b.hash(&mut h);
    h.finish()
}

/// One method probe: what the server returned at the URL that was asked for.
pub struct Probe {
    pub status: u16,
    /// Location header, when the server answered with a redirect.
    pub location: Option<String>,
    /// Allow header. RFC 9110 requires this on a 405, where it is the server
    /// naming the methods it permits, which beats inferring it from probes.
    pub allow: Option<String>,
    /// Protocol this response advertised, as (name, "header: value").
    pub protocol: Option<(String, String)>,
    /// Hash of the body, so callers can tell responses apart by content and not
    /// just by status.
    pub body_hash: u64,
    pub body_len: usize,
}

/// Send one request WITHOUT following redirects, so the reported status is the
/// one returned at the requested URL rather than the status of whatever page the
/// server pointed at. A transport failure comes back as status 0.
pub fn probe(method: &str, url: &str, cfg: &HttpConfig, rate: &mut RateLimiter) -> Probe {
    rate.wait();
    let send = || -> reqwest::Result<Probe> {
        let c = client(cfg, false)?;
        let m = Method::from_bytes(method.as_bytes()).unwrap_or(Method::GET);
        let resp = c.request(m, url).send()?;
        let status = resp.status().as_u16();
        let location = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let allow = resp
            .headers()
            .get(reqwest::header::ALLOW)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let protocol = protocol_of(|h| {
            resp.headers()
                .get(h)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.to_string())
        });
        let body = resp.bytes()?;
        Ok(Probe {
            status,
            location,
            allow,
            protocol,
            body_hash: hash_bytes(&body),
            body_len: body.len(),
        })
    };
    send().unwrap_or(Probe {
        status: 0,
        location: None,
        allow: None,
        protocol: None,
        body_hash: 0,
        body_len: 0,
    })
}

/// GET a URL (following redirects). 4xx/5xx are captured, not raised.
pub fn fetch(url: &str, cfg: &HttpConfig, rate: &mut RateLimiter) -> reqwest::Result<Fetched> {
    rate.wait();
    let resp = client(cfg, true)?.get(url).send()?;
    let requested = reqwest::Url::parse(url)
        .map(|u| u.to_string())
        .unwrap_or_else(|_| url.to_string());
    // Capture everything that borrows `resp` before `text()` consumes it.
    let status = resp.status().as_u16();
    let final_url = resp.url().to_string();
    let headers = resp.headers().clone();
    let is_https = final_url.starts_with("https://");
    let redirected = final_url != requested;
    let version = version_str(resp.version()).to_string();
    let body_len = resp.text().map(|t| t.len()).unwrap_or(0);
    Ok(Fetched {
        status,
        is_https,
        redirected,
        url: final_url,
        headers,
        body_len,
        version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn cfg() -> HttpConfig {
        HttpConfig {
            timeout: 5.0,
            insecure: true,
            headers: build_headers(None, &[], &[], None, None).unwrap(),
            http1_only: false,
        }
    }

    /// Serve one canned response on a throwaway port and return its URL.
    fn serve(response: &'static str) -> String {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", l.local_addr().unwrap());
        std::thread::spawn(move || {
            for s in l.incoming().take(4) {
                let mut s = match s {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf);
                let _ = s.write_all(response.as_bytes());
                let _ = s.flush();
            }
        });
        url
    }

    // Issue 1: the probe must report the status returned AT the requested URL.
    // Following the redirect would report 200 from a different page and hide
    // that this method is gated.
    #[test]
    fn probe_reports_the_redirect_not_its_destination() {
        let url = serve(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: /auth/login\r\nContent-Length: 0\r\n\r\n",
        );
        let mut rate = RateLimiter::new(0);
        let p = probe("GET", &url, &cfg(), &mut rate);
        assert_eq!(p.status, 307, "must not follow the redirect");
        assert_eq!(p.location.as_deref(), Some("/auth/login"));
    }

    // Issue 3: the probe reads the body, so identical responses hash the same
    // and callers can tell "actioned" from "rendered the same page".
    #[test]
    fn probe_hashes_the_body_so_identical_responses_match() {
        let url = serve("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
        let mut rate = RateLimiter::new(0);
        let a = probe("GET", &url, &cfg(), &mut rate);
        let b = probe("DELETE", &url, &cfg(), &mut rate);
        assert_eq!(a.status, 200);
        assert_eq!(a.body_len, 5);
        assert_eq!(a.body_hash, b.body_hash, "same bytes must hash the same");
    }

    // Issue 4: the negotiated protocol is named, since the header count depends
    // on it (hop-by-hop headers exist in 1.1 but not 2).
    #[test]
    fn version_is_named_for_the_report() {
        assert_eq!(version_str(reqwest::Version::HTTP_11), "HTTP/1.1");
        assert_eq!(version_str(reqwest::Version::HTTP_2), "HTTP/2");
    }
}
