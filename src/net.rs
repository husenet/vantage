//! HTTP fetch helpers, URL normalization, and a request-rate limiter.

use reqwest::blocking::{Client, Response};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, COOKIE};
use reqwest::Method;
use std::thread;
use std::time::{Duration, Instant};

pub const USER_AGENT: &str = "vantage/0.6 (+https://github.com/husenet/vantage)";

/// Shared request settings: timeout, TLS strictness, and the default headers
/// (User-Agent plus any auth the user passed).
pub struct HttpConfig {
    pub timeout: f64,
    pub insecure: bool,
    pub headers: HeaderMap,
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

fn client(cfg: &HttpConfig) -> reqwest::Result<Client> {
    Client::builder()
        .danger_accept_invalid_certs(cfg.insecure)
        .timeout(Duration::from_secs_f64(cfg.timeout))
        .default_headers(cfg.headers.clone())
        .build()
}

/// Send a single request (rate-limited). 4xx/5xx come back as a Response,
/// not an error; only transport-level failures error out.
pub fn request(
    method: &str,
    url: &str,
    cfg: &HttpConfig,
    rate: &mut RateLimiter,
) -> reqwest::Result<Response> {
    rate.wait();
    let c = client(cfg)?;
    let m = Method::from_bytes(method.as_bytes()).unwrap_or(Method::GET);
    c.request(m, url).send()
}

/// GET a URL (following redirects). 4xx/5xx are captured, not raised.
pub fn fetch(url: &str, cfg: &HttpConfig, rate: &mut RateLimiter) -> reqwest::Result<Fetched> {
    let resp = request("GET", url, cfg, rate)?;
    let requested = reqwest::Url::parse(url)
        .map(|u| u.to_string())
        .unwrap_or_else(|_| url.to_string());
    // Capture everything that borrows `resp` before `text()` consumes it.
    let status = resp.status().as_u16();
    let final_url = resp.url().to_string();
    let headers = resp.headers().clone();
    let is_https = final_url.starts_with("https://");
    let redirected = final_url != requested;
    let body_len = resp.text().map(|t| t.len()).unwrap_or(0);
    Ok(Fetched {
        status,
        is_https,
        redirected,
        url: final_url,
        headers,
        body_len,
    })
}
