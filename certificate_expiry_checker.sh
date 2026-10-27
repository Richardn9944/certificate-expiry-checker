#!/usr/bin/env bash
#
# certificate_expiry_checker.sh
# Shell library for parsing the expiration date from a TLS certificate
# presented by a remote host.
#
# Design decisions
# ----------------
# 1. We use `openssl s_client` to retrieve the certificate and `openssl x509`
#    to parse it. Both ship with the openssl command-line tool (core OpenSSL).
# 2. We connect using `-servername` for SNI support so that hosts serving
#    multiple certificates (virtual hosting) return the correct certificate.
# 3. We always use TLS 1.2 (-tls1_2) to guarantee a deterministic connection
#    method. This avoids ambiguous fallback behaviour that varies by OpenSSL
#    version and would make tests non-deterministic.
# 4. We expose two functions:
#      cert_expiry_get_date  host port  -> echoes YYYY-MM-DD, returns 0
#      cert_expiry_get_epoch host port  -> echoes epoch seconds, returns 0
#    On error, they echo nothing to stdout and return non-zero.
# 5. We redirect stderr to /dev/null for the openssl calls so that connection
#    noise doesn't pollute caller output. Callers who want error diagnostics
#    can inspect the exit code.
#
# Determinism note
# ----------------
# These functions perform real network I/O, so they are inherently
# non-deterministic and are NOT tested by the test suite directly. The test
# suite instead exercises the internal parsing function
# `cert_expiry_parse_enddate_string`, which converts an "openssl x509"
# end-date string into YYYY-MM-DD. That function is pure and deterministic.

set -euo pipefail

# Parse an OpenSSL end-date string into YYYY-MM-DD.
#
# OpenSSL prints certificate end dates in a format like:
#   "notAfter=Aug 14 12:00:00 2025 GMT"
# or, depending on locale/version:
#   "notAfter=Aug 14 12:00:00 2025 GMT"
#
# The month is always a three-letter English abbreviation regardless of
# system locale, because OpenSSL hardcodes English month names. We rely on
# that fact so parsing does not depend on the user's locale.
#
# Arguments:
#   $1 - the raw notAfter string, e.g. "notAfter=Aug 14 12:00:00 2025 GMT"
# Returns:
#   0 on success, echoing YYYY-MM-DD to stdout
#   1 on failure (empty output)
cert_expiry_parse_enddate_string() {
  local raw="${1:-}"
  local value
  local month day year
  local month_num

  # Strip leading "notAfter=" prefix if present.
  if [[ "$raw" == notAfter=* ]]; then
    value="${raw#notAfter=}"
  else
    value="$raw"
  fi

  # Trim leading/trailing whitespace.
  value="$(echo "$value" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"

  # The date should look like: "Aug 14 12:00:00 2025 GMT"
  # We only need month, day, year.
  read -r month day _time year _rest <<< "$value"

  if [[ -z "${month:-}" || -z "${day:-}" || -z "${year:-}" ]]; then
    return 1
  fi

  # Map English month abbreviations to numbers.
  case "$month" in
    Jan) month_num=01 ;;
    Feb) month_num=02 ;;
    Mar) month_num=03 ;;
    Apr) month_num=04 ;;
    May) month_num=05 ;;
    Jun) month_num=06 ;;
    Jul) month_num=07 ;;
    Aug) month_num=08 ;;
    Sep) month_num=09 ;;
    Oct) month_num=10 ;;
    Nov) month_num=11 ;;
    Dec) month_num=12 ;;
    *)   return 1 ;;
  esac

  # Zero-pad day if single digit.
  if [[ "${#day}" -eq 1 ]]; then
    day="0${day}"
  fi

  # Validate year is all digits and reasonable length.
  if [[ ! "$year" =~ ^[0-9]+$ ]]; then
    return 1
  fi
  if [[ "${#year}" -ne 4 ]]; then
    return 1
  fi

  printf '%s-%s-%s\n' "$year" "$month_num" "$day"
}

# Retrieve a certificate from host:port and echo the raw notAfter line.
#
# This function performs network I/O and is not tested by the suite.
# It uses TLS 1.2 and SNI for deterministic, correct certificate retrieval.
#
# Arguments:
#   $1 - hostname
#   $2 - port number
# Returns:
#   0 on success, echoing the notAfter line to stdout
#   non-zero on failure
cert_expiry_fetch_raw() {
  local host="$1"
  local port="$2"

  echo | openssl s_client -connect "${host}:${port}" -servername "$host" -tls1_2 2>/dev/null \
    | openssl x509 -noout -enddate 2>/dev/null
}

# Get the expiration date (YYYY-MM-DD) of a host's certificate.
#
# Arguments:
#   $1 - hostname
#   $2 - port number
# Returns:
#   0 on success, echoing YYYY-MM-DD to stdout
#   1 on failure
cert_expiry_get_date() {
  local host="$1"
  local port="$2"
  local raw
  local parsed

  raw="$(cert_expiry_fetch_raw "$host" "$port")" || return 1
  if [[ -z "$raw" ]]; then
    return 1
  fi

  parsed="$(cert_expiry_parse_enddate_string "$raw")" || return 1
  printf '%s\n' "$parsed"
}

# Get the expiration date as Unix epoch seconds.
#
# We convert YYYY-MM-DD to epoch using `date -d`. GNU date accepts the
# YYYY-MM-DD format directly. On systems with non-GNU date (e.g. macOS),
# this may not work; we document this limitation in the README.
#
# Arguments:
#   $1 - hostname
#   $2 - port number
# Returns:
#   0 on success, echoing epoch seconds to stdout
#   1 on failure
cert_expiry_get_epoch() {
  local host="$1"
  local port="$2"
  local date_str
  local epoch

  date_str="$(cert_expiry_get_date "$host" "$port")" || return 1
  if [[ -z "$date_str" ]]; then
    return 1
  fi

  epoch="$(date -d "$date_str" +%s 2>/dev/null || true)"
  if [[ -z "$epoch" ]]; then
    return 1
  fi
  printf '%s\n' "$epoch"
}
