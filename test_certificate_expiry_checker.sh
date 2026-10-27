#!/usr/bin/env bash
#
# Tests for certificate_expiry_checker.sh
#
# We test the pure parsing function, cert_expiry_parse_enddate_string, which
# converts OpenSSL's notAfter line into YYYY-MM-DD. The network functions
# (cert_expiry_fetch_raw, cert_expiry_get_date, cert_expiry_get_epoch) perform
# real I/O and are not tested here because they are inherently non-deterministic.

set -euo pipefail

# Source the library under test.
# shellcheck source=certificate_expiry_checker.sh
source "$(dirname "$0")/certificate_expiry_checker.sh"

# Test counter and TAP-like output.
_test_count=0
_pass_count=0

assert_eq() {
  local expected="$1"
  local actual="$2"
  local label="${3:-test}"
  _test_count=$(( _test_count + 1 ))

  if [[ "$expected" == "$actual" ]]; then
    _pass_count=$(( _pass_count + 1 ))
    printf 'ok %d - %s\n' "$_test_count" "$label"
  else
    printf 'not ok %d - %s\n' "$_test_count" "$label"
    printf '  ---\n' 
    printf '  expected: %q\n' "$expected"
    printf '  got:      %q\n' "$actual"
    printf '  ...\n'
    exit 1
  fi
}

# ---- Tests for cert_expiry_parse_enddate_string ----

# Happy path: typical notAfter string.
result="$(cert_expiry_parse_enddate_string 'notAfter=Aug 14 12:00:00 2025 GMT')"
assert_eq '2025-08-14' "$result" 'parses typical notAfter string'

# Another month.
result="$(cert_expiry_parse_enddate_string 'notAfter=Jan  1 00:00:00 2030 GMT')"
assert_eq '2030-01-01' "$result" 'parses January with extra space'

# Single-digit day should be zero-padded.
result="$(cert_expiry_parse_enddate_string 'notAfter=Mar 5 09:30:00 2024 GMT')"
assert_eq '2024-03-05' "$result" 'zero-pads single-digit day'

# December (last month of year).
result="$(cert_expiry_parse_enddate_string 'notAfter=Dec 31 23:59:59 2023 GMT')"
assert_eq '2023-12-31' "$result" 'parses December 31'

# String without the notAfter= prefix (bare date) should also parse.
result="$(cert_expiry_parse_enddate_string 'Aug 14 12:00:00 2025 GMT')"
assert_eq '2025-08-14' "$result" 'parses bare date without notAfter prefix'

# Every month maps to the correct number.
result="$(cert_expiry_parse_enddate_string 'notAfter=Feb 28 12:00:00 2025 GMT')"
assert_eq '2025-02-28' "$result" 'February maps to 02'

result="$(cert_expiry_parse_enddate_string 'notAfter=Apr 15 12:00:00 2025 GMT')"
assert_eq '2025-04-15' "$result" 'April maps to 04'

result="$(cert_expiry_parse_enddate_string 'notAfter=May 10 12:00:00 2025 GMT')"
assert_eq '2025-05-10' "$result" 'May maps to 05'

result="$(cert_expiry_parse_enddate_string 'notAfter=Jun  1 12:00:00 2025 GMT')"
assert_eq '2025-06-01' "$result" 'June maps to 06'

result="$(cert_expiry_parse_enddate_string 'notAfter=Jul  4 12:00:00 2025 GMT')"
assert_eq '2025-07-04' "$result" 'July maps to 07'

result="$(cert_expiry_parse_enddate_string 'notAfter=Sep  9 12:00:00 2025 GMT')"
assert_eq '2025-09-09' "$result" 'September maps to 09'

result="$(cert_expiry_parse_enddate_string 'notAfter=Oct 31 12:00:00 2025 GMT')"
assert_eq '2025-10-31' "$result" 'October maps to 10'

result="$(cert_expiry_parse_enddate_string 'notAfter=Nov 11 12:00:00 2025 GMT')"
assert_eq '2025-11-11' "$result" 'November maps to 11'

# ---- Failure cases ----

# Unknown month abbreviation should return failure.
if cert_expiry_parse_enddate_string 'notAfter=Xxx 14 12:00:00 2025 GMT' >/dev/null 2>&1; then
  assert_eq 'fail' 'should_have_failed' 'rejects unknown month abbreviation'
else
  assert_eq 'fail' 'fail' 'rejects unknown month abbreviation (correctly)'
fi

# Empty string should return failure.
if cert_expiry_parse_enddate_string '' >/dev/null 2>&1; then
  assert_eq 'fail' 'should_have_failed' 'rejects empty input'
else
  assert_eq 'fail' 'fail' 'rejects empty input (correctly)'
fi

# Garbage string should return failure.
if cert_expiry_parse_enddate_string 'this is not a date' >/dev/null 2>&1; then
  assert_eq 'fail' 'should_have_failed' 'rejects garbage input'
else
  assert_eq 'fail' 'fail' 'rejects garbage input (correctly)'
fi

# Two-digit year should be rejected (we require 4-digit years).
if cert_expiry_parse_enddate_string 'notAfter=Aug 14 12:00:00 25 GMT' >/dev/null 2>&1; then
  assert_eq 'fail' 'should_have_failed' 'rejects two-digit year'
else
  assert_eq 'fail' 'fail' 'rejects two-digit year (correctly)'
fi

# Summary
printf '\n# %d/%d tests passed\n' "$_pass_count" "$_test_count"

if [[ "$_pass_count" -eq "$_test_count" ]]; then
  exit 0
else
  exit 1
fi
