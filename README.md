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
                  _
__   ____ _ _ __ | |_ __ _  __ _  ___
\ \ / / _` | '_ \| __/ _` |/ _` |/ _ \
 \ V / (_| | | | | || (_| | (_| |  __/
  \_/ \__,_|_| |_|\__\__,_|\__, |\___|
                           |___/
  Web security scanner

Target: https://example.com
HTTP 200

== HTTP headers ================================================
  11 response headers
  accept-ranges: bytes
  allow: GET, HEAD
  content-type: text/html
  server: cloudflare
  ...

  security headers
  - strict-transport-security
  - content-security-policy
  - x-frame-options
  - x-content-type-options
  - referrer-policy
  - permissions-policy
  - cross-origin-opener-policy
  - cross-origin-embedder-policy
  - cross-origin-resource-policy

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
cargo run --locked --release -- example.com
```

Or install the `vantage` command onto your PATH:

```bash
cargo install --locked --path .
vantage example.com
```

The result is a single static binary (TLS is pure-Rust via rustls, so there is no
OpenSSL system dependency to install).

---

## Checks (flags)

| Flag | What it does |
|------|--------------|
| `--headers` | Full response-header dump + security-header matrix (HSTS, CSP, XFO, X-CTO, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP). Values are checked, not just presence, so an off-by-default value like `COEP: unsafe-none` reports as ineffective rather than passing |
| `--cookies` | Cookie flags: Secure, HttpOnly, SameSite |
| `--cors` | CORS configuration (wildcard, `null`, http origin, credentials); sends one extra request with an `Origin` header to catch servers that reflect any origin |
| `--disclosure` | Server / framework headers (Server, X-Powered-By, Via, ...) |
| `--csp` | Parse the CSP and flag `unsafe-inline`/`unsafe-eval`, wildcards, `http:`, missing `default-src` |
| `--hsts` | Parse + grade HSTS (`max-age`, `includeSubDomains`, `preload`) |
| `--methods` | Per-method probe; `--active` adds POST/PUT/DELETE/PATCH. Reports the status only, since a label like "blocked" just restates the code. Redirects are not followed, so the status is the one returned at the URL you asked for, annotated with its target (`307 GET -> /auth/login`). A write method whose body matches GET is annotated `same body as GET`, since a 200 there actioned nothing. The server's own `Allow` header is reported when it sends one (RFC 9110 requires it on a 405). Detected protocols (tus, WebDAV, OData, gRPC, S3, Azure Storage, Elasticsearch, CouchDB, WebSocket, Kubernetes, Vault) are named, because several reject a request that omits their protocol header before weighing the method |
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
| `--http1` | Force HTTP/1.1 instead of negotiating HTTP/2. The status line names the protocol, since hop-by-hop headers (`Connection`, `Transfer-Encoding`) exist in 1.1 but not 2, so the header count differs between them |
| `--json` | Machine-readable JSON |
| `--no-color` | Disable ANSI colors |

## Authenticated scans

The HTTP checks (headers, cookies, CORS, CSP, HSTS, methods) run against
whatever session you give it, so you can hit pages behind a login. Pass a
session cookie, a bearer/basic token, or arbitrary headers:

```bash
vantage app.example.com --cookie "session=abc123"
vantage app.example.com --cookie "sid=abc; csrf=xyz; theme=dark"   # paste a whole cookie string
vantage api.example.com --bearer "$TOKEN" --methods --active
vantage app.example.com --header "X-Api-Key: k" --header "X-Env: staging"
vantage app.example.com --basic "admin:s3cret"
```

Note the singular/plural: **`--cookie`** (singular) *sends* cookies with the
request; **`--cookies`** (plural) is the check that *audits* the server's
Set-Cookie flags and takes no value. You can paste a full cookie string into one
`--cookie`, with or without a leading `Cookie:`; the domain still goes first.

Credentials go on every request. It warns you if you send them over plaintext
`http://`. The cookie check singles out any cookie you pass with `--cookie`: if
the server re-issues it, its Secure/HttpOnly/SameSite flags are graded; if not,
it says so, since those flags only show up on the server's `Set-Cookie`.

## Releasing

`scripts/release.sh` runs the pre-release checks, builds, and writes the zip:

```bash
cargo install cargo-audit --locked    # once
./scripts/release.sh
```

It stops the release on a dirty working tree, a failing test, or any RustSec
advisory against the dependency tree (`cargo audit --deny warnings`, which also
covers unmaintained, unsound, and yanked crates). rustfmt and clippy are
reported but do not block. Audit runs every time rather than once, since new
advisories land against code that has not changed.

`--locked` matters on the install path: `cargo install` ignores `Cargo.lock`
unless told not to, so without it a client compiles whatever versions resolve
that day rather than the audited tree.

One provenance caveat if a Windows build is ever cut: `ring` ships 17
pregenerated NASM object files and links them on Windows x86/x86_64 instead of
assembling the `.asm` next to them. The Linux build assembles from `.S` source
and never touches them.

## License

[MIT](LICENSE) (c) husenet
