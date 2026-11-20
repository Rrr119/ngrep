#!/bin/bash
#
# pcap-based regression tests for:
#   1. five-tuple + payload combination matching (-Y)
#   2. PCRE-style "only matching" output (-o), incl. capture groups
#   3. IPv6 / binary (-X) / wildcard / existing-flag compatibility
#
# Fixtures are generated on the fly by make_pcaps.py (stdlib-only Python).

set -u

cd "$(dirname "$0")/.."

NGREP="${NGREP:-./ngrep}"
PCAP_DIR="tests/pcaps"

if [ ! -x "$NGREP" ]; then
    echo "ngrep binary not found at $NGREP; run 'make' first" >&2
    exit 2
fi

python3 tests/make_pcaps.py "$PCAP_DIR" >/dev/null || exit 2

TCP_FLOW="$PCAP_DIR/tcp-flow.pcap"
UDP_PCRE="$PCAP_DIR/udp-pcre.pcap"
IPV6_BIN="$PCAP_DIR/ipv6-binary.pcap"

tests_run=0
tests_failed=0

# assert_contains <name> <needle> <output>
assert_contains() {
    local name="$1" needle="$2" output="$3"
    tests_run=$((tests_run + 1))
    if printf '%s' "$output" | grep -Fq -- "$needle"; then
        echo "ok   - $name"
    else
        echo "FAIL - $name (missing: $needle)"
        echo "----- output -----"
        printf '%s\n' "$output"
        echo "------------------"
        tests_failed=$((tests_failed + 1))
    fi
}

# assert_not_contains <name> <needle> <output>
assert_not_contains() {
    local name="$1" needle="$2" output="$3"
    tests_run=$((tests_run + 1))
    if printf '%s' "$output" | grep -Fq -- "$needle"; then
        echo "FAIL - $name (unexpected: $needle)"
        echo "----- output -----"
        printf '%s\n' "$output"
        echo "------------------"
        tests_failed=$((tests_failed + 1))
    else
        echo "ok   - $name"
    fi
}

# assert_count <name> <pattern> <expected> <output>
assert_count() {
    local name="$1" pattern="$2" expected="$3" output="$4"
    local actual
    actual=$(printf '%s' "$output" | grep -c -- "$pattern" || true)
    tests_run=$((tests_run + 1))
    if [ "$actual" -eq "$expected" ]; then
        echo "ok   - $name"
    else
        echo "FAIL - $name (expected $expected '$pattern', got $actual)"
        echo "----- output -----"
        printf '%s\n' "$output"
        echo "------------------"
        tests_failed=$((tests_failed + 1))
    fi
}

# assert_exit <name> <expected-code> <ngrep args...>
assert_exit() {
    local name="$1" expected="$2"; shift 2
    "$NGREP" "$@" >/dev/null 2>&1
    local code=$?
    tests_run=$((tests_run + 1))
    if [ "$code" -eq "$expected" ]; then
        echo "ok   - $name"
    else
        echo "FAIL - $name (expected exit $expected, got $code)"
        tests_failed=$((tests_failed + 1))
    fi
}

echo "== pcap 1/3: TCP five-tuple + payload combination ($TCP_FLOW) =="

out=$("$NGREP" -qq -Y 'tcp,10.0.0.1,12345,10.0.0.2,80' 'user=admin' -I "$TCP_FLOW")
assert_count    "tuple AND payload yields exactly one packet" '^T ' 1 "$out"
assert_contains "matched packet is the correct five-tuple" '10.0.0.1:12345 -> 10.0.0.2:80' "$out"
assert_contains "matched packet keeps payload output" 'user=admin' "$out"

out=$("$NGREP" -qq -Y 'tcp,10.0.0.1,12345,10.0.0.2,80' -I "$TCP_FLOW")
assert_count "flow filter without payload matches both flow packets" '^T ' 2 "$out"

out=$("$NGREP" -qq -Y 'tcp,10.0.0.1,12345,10.0.0.2,80' 'GET' -I "$TCP_FLOW")
assert_count "payload filter alone rejects tuple-matching packet" '^T ' 1 "$out"
assert_contains "second flow packet matches GET" 'GET /index.html' "$out"

out=$("$NGREP" -qq -Y 'udp,10.0.0.1,12345,10.0.0.2,80' 'user=admin' -I "$TCP_FLOW")
assert_count "protocol component of tuple is enforced" '^U ' 1 "$out"

out=$("$NGREP" -qq -Y 'tcp,10.0.0.2,80,10.0.0.1,12345' 'user=admin' -I "$TCP_FLOW")
assert_count "reversed tuple only matches reversed packet" '^T ' 1 "$out"
assert_contains "reversed tuple selects packet #3" '10.0.0.2:80 -> 10.0.0.1:12345' "$out"

out=$("$NGREP" -qq -Y '*,10.0.0.1,*,10.0.0.2,*' 'user=admin' -I "$TCP_FLOW")
assert_count "wildcard tuple matches tcp and udp flows" '^[TU] ' 3 "$out"

out=$("$NGREP" -qq -v -Y 'tcp,10.0.0.1,12345,10.0.0.2,80' 'user=admin' -I "$TCP_FLOW")
assert_count "-v inverts the combined tuple+payload match" '^[TU] ' 1 "$out"
assert_contains "inverted match keeps the non-matching flow packet" 'GET /index.html' "$out"

# A blank match expression is required so 'tcp' is parsed as the BPF filter.
out=$("$NGREP" -qq -Y 'tcp,10.0.0.1,*,10.0.0.2,*' '' 'tcp' -I "$TCP_FLOW")
assert_count "-Y coexists with a BPF filter" '^T ' 3 "$out"

out=$("$NGREP" -qq -i -o -n 1 'HTTP' -I "$TCP_FLOW")
assert_count "-i/-n remain compatible with -o" 'match\[' 1 "$out"
assert_contains "-o reports match offset and length" 'match[12:4]: HTTP' "$out"

out=$("$NGREP" -qq -A 1 -Y 'tcp,10.0.0.1,12345,10.0.0.2,80' 'user=admin' -I "$TCP_FLOW")
assert_count "-A trailing context still works alongside -Y" '^T ' 2 "$out"

out=$("$NGREP" -Y 'tcp,10.0.0.1,12345,10.0.0.2,80' 'x' -I "$TCP_FLOW" 2>&1)
assert_contains "startup prints the active flow filter" 'flow: tcp,10.0.0.1,12345,10.0.0.2,80' "$out"

echo
echo "== pcap 2/3: UDP PCRE-only output ($UDP_PCRE) =="

out=$("$NGREP" -qq -o 'secret=[a-z0-9]+' -I "$UDP_PCRE")
assert_count    "-o prints every match (two in one packet)" 'match\[' 3 "$out"
assert_contains "first match rendered with offset/length" 'match[0:14]: secret=hunter2' "$out"
assert_contains "second match rendered with offset/length" 'match[19:14]: secret=hunter3' "$out"
assert_not_contains "-o suppresses normal payload dumps" 'secret=hunter2 and' "$out"

out=$("$NGREP" -qq -o 'name=([a-z.]+)' -I "$UDP_PCRE")
assert_contains "full match line is preserved" 'match[6:22]: name=alpha.example.com' "$out"
assert_contains "capture group is printed with its own offset" 'group[1][11:17]: alpha.example.com' "$out"

out=$("$NGREP" -qq -o 'secret=[a-z0-9]+' -I "$UDP_PCRE")
assert_count "-o only emits lines for matching packets" '^U ' 2 "$out"

out=$("$NGREP" -qq -Y 'udp,192.168.1.10,*,8.8.8.8,53' -o 'secret=[a-z0-9]+' -I "$UDP_PCRE")
assert_count "-Y and -o combine on the matching five-tuple" 'match\[' 2 "$out"
assert_not_contains "different destination host is filtered out by -Y" 'only-on-other-dns' "$out"

out=$("$NGREP" -qq -o -v 'secret' -I "$UDP_PCRE")
assert_count "-o with -v emits no match lines" 'match\[' 0 "$out"
assert_count "-o with -v still shows inverted packet headers" '^U ' 2 "$out"

out=$("$NGREP" -qq -o '' -I "$UDP_PCRE")
assert_count "blank match expression emits no zero-length -o lines" 'match\[' 0 "$out"
assert_count "blank match expression still lists every packet header" '^U ' 4 "$out"

echo
echo "== pcap 3/3: IPv6 + binary + wildcard compatibility ($IPV6_BIN) =="

out=$("$NGREP" -qq -X -o 'deadbeef' -I "$IPV6_BIN")
assert_count "-X -o finds every binary marker (v4+v6, tcp+udp)" 'match\[' 4 "$out"
assert_contains "binary match is escaped for terminal output" 'match[0:4]: \xde\xad\xbe\xef' "$out"
assert_contains "offset past payload start is reported" 'match[7:4]: \xde\xad\xbe\xef' "$out"

out=$("$NGREP" -qq -Y 'udp,2001:db8::1,*,2001:db8::2,*' -X -o 'deadbeef' -I "$IPV6_BIN")
assert_count "IPv6 five-tuple + binary + -o combination" 'match\[' 2 "$out"
assert_not_contains "TCP marker excluded by udp tuple" 'over tcp' "$out"
assert_not_contains "IPv4 marker excluded by IPv6 tuple" 'over v4' "$out"

out=$("$NGREP" -qq -Y '*,2001:db8::1,*,2001:db8::2,*' -I "$IPV6_BIN")
assert_count "wildcard proto tuple covers udp, tcp and icmpv6" '^[UTI] ' 4 "$out"

out=$("$NGREP" -qq -Y 'icmpv6,2001:db8::1,*,2001:db8::2,*' -I "$IPV6_BIN")
assert_count "named icmpv6 protocol in tuple" '^I ' 1 "$out"

out=$("$NGREP" -qq -x -X 'deadbeef' -I "$IPV6_BIN")
assert_count "existing -x hexdump remains compatible with -X" '^[UTI] ' 4 "$out"
assert_contains "hexdump renders the marker bytes" 'de ad be ef' "$out"

out=$("$NGREP" -qq -Y 'tcp,2001:db8::1,*,2001:db8::2,*' -I "$IPV6_BIN")
assert_count "existing payload-less invocation under -Y still works" '^T ' 1 "$out"

echo
echo "== malformed -Y specifications =="

assert_exit "wrong field count is rejected" 2 -qq -Y 'tcp,10.0.0.1,12345,10.0.0.2' -I "$TCP_FLOW"
assert_exit "invalid IP address is rejected"  2 -qq -Y 'tcp,not-an-ip,1,10.0.0.2,80' -I "$TCP_FLOW"
assert_exit "invalid protocol is rejected"    2 -qq -Y 'foo,*,*,*,*' -I "$TCP_FLOW"
assert_exit "invalid port is rejected"        2 -qq -Y 'tcp,*,99999,*,80' -I "$TCP_FLOW"

echo
if [ "$tests_failed" -eq 0 ]; then
    echo "ALL $tests_run TESTS PASSED"
    exit 0
fi

echo "$tests_failed/$tests_run TESTS FAILED"
exit 1
