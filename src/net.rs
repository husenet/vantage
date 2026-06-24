//! HTTP fetch helpers, URL normalization, and a request-rate limiter.

use reqwest::blocking::{Client, Response};
use reqwest::header::HeaderMap;
use reqwest::Method;
use std::thread;
use std::time::{Duration, Instant};

pub const USER_AGENT: &str = "vantage/0.3 (+https://github.com/husenet/vantage)";

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

fn client(timeout: f64, insecure: bool) -> reqwest::Result<Client> {
    Client::builder()
        .danger_accept_invalid_certs(insecure)
        .timeout(Duration::from_secs_f64(timeout))
        .user_agent(USER_AGENT)
        .build()
}

/// Send a single request (rate-limited). 4xx/5xx come back as a Response,
/// not an error; only transport-level failures error out.
pub fn request(
    method: &str,
    url: &str,
    timeout: f64,
    insecure: bool,
    rate: &mut RateLimiter,
) -> reqwest::Result<Response> {
    rate.wait();
    let c = client(timeout, insecure)?;
    let m = Method::from_bytes(method.as_bytes()).unwrap_or(Method::GET);
    c.request(m, url).send()
}

/// GET a URL (following redirects). 4xx/5xx are captured, not raised.
pub fn fetch(
    url: &str,
    timeout: f64,
    insecure: bool,
    rate: &mut RateLimiter,
) -> reqwest::Result<Fetched> {
    let resp = request("GET", url, timeout, insecure, rate)?;
    let requested = reqwest::Url::parse(url)
        .map(|u| u.to_string())
        .unwrap_or_else(|_| url.to_string());
    let final_url = resp.url().to_string();
    Ok(Fetched {
        status: resp.status().as_u16(),
        is_https: final_url.starts_with("https://"),
        redirected: final_url != requested,
        url: final_url,
        headers: resp.headers().clone(),
    })
}
