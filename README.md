# xss — fast XSS reflection pre-filter

A Go tool that reads a mass of URLs (from recon/wayback/gau exports), injects a
probe payload into each parameter, and tells you **which URLs reflect it back** —
at machine speed.

> **Positioning:** this is a *speed filter*, not a verifier. A reflection means
> "look here". For full context-aware XSS verification (HTML body / attribute /
> JS contexts, proper payloads per context, DOM XSS, reports) use
> [secscan](https://github.com/Kcoof/security-scanner).

```
[REFLECTS] https://target.com/search?q=%22%3E%3C%28%29kcoof  (param: q)
[  clean ] https://target.com/page?id=...
```

## How it tests

- URLs containing a `FUZZ` placeholder → the placeholder is replaced with the payload.
- URLs with a query string → **each parameter** is injected one at a time.
- Static assets (images, css, js files, archives...) are skipped.
- A hit = payload string found unencoded in the response body.

## Build & usage

```bash
go build -o xss .

xss -l urls.txt                          # print reflecting URLs
cat urls.txt | xss -                     # stdin, pipe-friendly
xss -l urls.txt -o reflecting.txt        # save hits for deep testing
xss -l urls.txt -p '"><svg onload=1>' -t 40 -timeout 8
xss -l urls.txt -a                       # also show clean URLs
```

| Flag | Purpose |
|---|---|
| `-l` | URL file, or `-` for stdin |
| `-o` | Save reflecting URLs to file |
| `-p` | Probe payload (default `"><()kcoof`) |
| `-t` | Concurrency (default 20) |
| `-timeout` | Per-request timeout seconds (default 10) |
| `-a` | Print non-reflecting URLs too |

## Pipeline

Part of the Kcoof bug bounty toolkit:

```bash
# 1. recon: subdomains + alive hosts
subenum -d target.com -probe -w sub_arch.txt

# 2. collect URLs (gau/waymore) or use alive list, mass-filter for reflections
xss -l urls.txt -o reflecting.txt

# 3. deep, context-aware verification + full vuln scan
python -m secscan reflecting.txt --oob -o reports
```

## Legal

For authorized security testing only.
