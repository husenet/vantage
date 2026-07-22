# vantage

> A command-line web security scanner - headers, CSP, HSTS, HTTP methods, CORS,
> cookies, DNS recon, and nmap/vulners - in one tool.

`vantage` is a single Rust binary (one self-contained executable, no runtime to
install). You pick checks with flags; output is grouped into clean, separated
sections that read well in a report.

```
vantage example.com                      # default HTTP audit
vantage example.com example.org          # several targets at once
vantage example.com --all                # everything
vantage example.com --dnsrecon --nmap    # just those checks
vantage example.com --vulners            # nmap -sV --script vulners
```

---

## Sample output

A default run prints the security-header matrix and the passive HTTP checks, each
in its own section with no severity labels - made to drop straight into a report:

```text
$ vantage example.com
Target: https://example.com
█   █  ███  █   █ █████  ███   ████ █████
█   █ █   █ ██  █   █   █   █ █     █    
█   █ █████ █ █ █   █   █████ █ ███ ████ 
 █ █  █   █ █  ██   █   █   █ █   █ █    
  █   █   █ █   █   █   █   █  ████ █████

HTTP 200

== HTTP headers ================================================
  11 response headers
  accept-ranges: bytes
  allow: GET, HEAD
  content-type: text/html
  server: cloudflare
  ...

  security headers
  - strict-transport-security  (HSTS - forces HTTPS)
  - content-security-policy  (CSP - mitigates XSS / injection)
  - x-frame-options  (clickjacking protection)
  - x-content-type-options  (MIME-sniffing protection)
  - referrer-policy  (controls referrer leakage)
  - permissions-policy  (restricts powerful browser features)
  - cross-origin-opener-policy  (COOP)
  - cross-origin-embedder-policy  (COEP)
  - cross-origin-resource-policy  (CORP)

== Cookies =====================================================
    no Set-Cookie headers

== CORS ========================================================
    no Access-Control-Allow-Origin header

== Information disclosure ======================================
  server: cloudflare

== Content-Security-Policy =====================================
  - no Content-Security-Policy header

== HSTS (Strict-Transport-Security) ============================
  - no Strict-Transport-Security header
```

Adding `--all` layers on DNS recon, an nmap service + vulners scan, and HTTP-method
probing (with a live spinner while the external tools run). See
[`docs/sample-output.txt`](docs/sample-output.txt) for a full `--all` capture.

---

## Install / run

A Linux command-line tool. Needs a Rust toolchain (1.74+) and the `nmap` and
`nslookup` packages, which the `--nmap`/`--vulners` and `--dnsrecon` checks call:

```bash
sudo apt install nmap dnsutils      # Debian / Ubuntu / Kali
```

Run straight from a clone:

```bash
cargo run --release -- example.com
```

Or install the `vantage` command onto your PATH:

```bash
cargo install --path .
vantage example.com
```

The result is a single static binary (TLS is pure-Rust via rustls, so there is no
OpenSSL system dependency to install).

---

## Checks (flags)

| Flag | What it does |
|------|--------------|
| `--headers` | Full response-header dump + security-header matrix (HSTS, CSP, XFO, X-CTO, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP) |
| `--cookies` | Cookie flags: Secure, HttpOnly, SameSite |
| `--cors` | CORS configuration (wildcard origin, wildcard + credentials) |
| `--disclosure` | Server / framework headers (Server, X-Powered-By, Via, ...) |
| `--csp` | Parse the CSP and flag `unsafe-inline`/`unsafe-eval`, wildcards, `http:`, missing `default-src` |
| `--hsts` | Parse + grade HSTS (`max-age`, `includeSubDomains`, `preload`) |
| `--methods` | Allowed HTTP methods (OPTIONS `Allow` + per-method probe); `--active` adds POST/PUT/DELETE/PATCH |
| `--dnsrecon` | DNS records (A/AAAA/NS/MX/TXT/SOA/CNAME) via nslookup |
| `--nmap` | nmap `-sV` service scan (nmap's default ports; see `--ports`/`--all-ports`) |
| `--vulners` | `nmap -sV --script vulners` (CVE matching) over the same ports |
| `--all` | Run every check |

With **no module flags**, vantage runs the default HTTP audit:
`headers + cookies + cors + disclosure + csp + hsts`.

## Options

| Option | Description |
|--------|-------------|
| `--ports <spec>` | Port spec for `--nmap`/`--vulners` in nmap `-p` syntax (e.g. `80,443` or `1-1024`); default is nmap's normal set |
| `--all-ports` | Scan all 65535 ports with `--nmap`/`--vulners` (nmap `-p-`) |
| `--header "N: V"` | Send a custom request header (repeatable) |
| `--cookie "n=v"` | Send a cookie (repeatable; collapsed into one `Cookie` header) |
| `--bearer <token>` | Shortcut for `Authorization: Bearer <token>` |
| `--basic <user:pass>` | Shortcut for `Authorization: Basic` (base64-encoded) |
| `--user-agent <ua>` | Override the `User-Agent` header |
| `--rate <n>` | Throttle HTTP requests to N per minute (0 = unlimited) |
| `--active` | With `--methods`, also probe POST/PUT/DELETE/PATCH |
| `--timeout <s>` | Per-request timeout (default 15) |
| `--insecure` | Accept invalid/self-signed TLS certificates |
| `--json` | Machine-readable JSON |
| `--no-color` | Disable ANSI colors |

## Authenticated scans

The HTTP checks (headers, cookies, CORS, CSP, HSTS, methods) run against
whatever session you give it, so you can hit pages behind a login. Pass a
session cookie, a bearer/basic token, or arbitrary headers:

```bash
vantage app.example.com --cookie "session=abc123" --headers --cookies
vantage api.example.com --bearer "$TOKEN" --methods --active
vantage app.example.com --header "X-Api-Key: k" --header "X-Env: staging"
vantage app.example.com --basic "admin:s3cret"
```

Credentials go on every request. It warns you if you send them over plaintext
`http://`. The cookie check singles out any cookie you pass with `--cookie`: if
the server re-issues it, its Secure/HttpOnly/SameSite flags are graded; if not,
it says so, since those flags only show up on the server's `Set-Cookie`.

## License

[MIT](LICENSE) (c) husenet
