# certificate-expiry-checker

Parses the expiration date from a TLS certificate presented by a remote host.

## Usage

```bash
source ./certificate_expiry_checker.sh

# Get the expiration date as YYYY-MM-DD
cert_expiry_get_date "example.org" 443

# Get the expiration date as Unix epoch seconds
cert_expiry_get_epoch "example.org" 443
```

## Why this exists

Monitoring TLS certificate expiration is a common operational need. This library provides a small, focused interface for extracting the expiration date from a live certificate, using only `openssl` (which is already present on virtually every Linux system) and bash builtins.

The trade-off: we pin to TLS 1.2 for deterministic connection behaviour. This means very old servers that only support TLS 1.0/1.1 will not work. We consider that acceptable — TLS 1.0/1.1 are deprecated and modern certificates should not be served over them.

## Awkward edges

- **OpenSSL locale**: OpenSSL always outputs English month abbreviations regardless of system locale, so parsing does not depend on `LANG` or `LC_*`. This is relied upon.
- **GNU date requirement**: `cert_expiry_get_epoch` uses `date -d`, which requires GNU coreutils. On macOS or BSD-only systems, this function will fail.
- **SNI**: `cert_expiry_get_date` and `cert_expiry_get_epoch` send the hostname via SNI (`-servername`), so virtual-hosted certificates resolve correctly.
- **No retry**: If the connection fails, the functions return non-zero immediately. Callers are responsible for retry logic.

## Exported functions

- `cert_expiry_parse_enddate_string <notAfter-string>` — Pure parsing function. Converts an OpenSSL notAfter line (e.g. `notAfter=Aug 14 12:00:00 2025 GMT`) into `YYYY-MM-DD`. Returns 0 on success, 1 on failure.
- `cert_expiry_fetch_raw <host> <port>` — Retrieves the raw notAfter line from a remote host. Returns 0 on success, non-zero on failure.
- `cert_expiry_get_date <host> <port>` — Retrieves and parses the expiration date. Echoes `YYYY-MM-DD`. Returns 0 on success, 1 on failure.
- `cert_expiry_get_epoch <host> <port>` — Retrieves the expiration date as Unix epoch seconds. Echoes an integer. Returns 0 on success, 1 on failure. Requires GNU `date`.

## Running tests

```bash
bash test_certificate_expiry_checker.sh
```

The tests exercise the pure parsing function. Network functions are not tested because they require live I/O.
