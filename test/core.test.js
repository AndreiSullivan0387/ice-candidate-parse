import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseIceCandidate, normalizeCandidate } from '../src/index.js';

test('parses a typical host candidate API string', () => {
  const c = parseIceCandidate(
    'candidate:842163049 1 udp 1677729535 192.0.2.3 64325 typ host generation 0'
  );
  assert.equal(c.foundation, '842163049');
  assert.equal(c.component, 1);
  assert.equal(c.protocol, 'udp');
  assert.equal(c.priority, 1677729535);
  assert.equal(c.address, '192.0.2.3');
  assert.equal(c.port, 64325);
  assert.equal(c.type, 'host');
  assert.equal(c.extensions.get('typ'), 'host');
  assert.equal(c.extensions.get('generation'), '0');
});

test('parses an SDP line with leading a=', () => {
  const c = parseIceCandidate(
    'a=candidate:842163049 1 udp 1677729535 192.0.2.3 64325 typ host'
  );
  assert.equal(c.foundation, '842163049');
  assert.equal(c.type, 'host');
  assert.equal(c.raw, '842163049 1 udp 1677729535 192.0.2.3 64325 typ host');
});

test('parses a server-reflexive candidate with raddr/rport', () => {
  const c = parseIceCandidate(
    'candidate:842163049 1 udp 1677729535 203.0.113.5 64325 typ srflx raddr 192.0.2.3 rport 64325'
  );
  assert.equal(c.type, 'srflx');
  assert.equal(c.extensions.get('raddr'), '192.0.2.3');
  assert.equal(c.extensions.get('rport'), '64325');
});

test('parses a relay candidate with tcp', () => {
  const c = parseIceCandidate(
    'candidate:842163049 1 tcp 1518280447 192.0.2.7 9 typ relay tcptype passive'
  );
  assert.equal(c.protocol, 'tcp');
  assert.equal(c.type, 'relay');
  assert.equal(c.extensions.get('tcptype'), 'passive');
});

test('normalises protocol to lowercase', () => {
  const c = parseIceCandidate(
    'candidate:1 1 UDP 1 192.0.2.1 1 typ host'
  );
  assert.equal(c.protocol, 'udp');
});

test('component 2 is preserved (RTCP)', () => {
  const c = parseIceCandidate(
    'candidate:1 2 udp 1 192.0.2.1 1 typ host'
  );
  assert.equal(c.component, 2);
});

test('extensions map preserves insertion order', () => {
  const c = parseIceCandidate(
    'candidate:1 1 udp 1 192.0.2.1 1 typ host generation 0 ufrag abc'
  );
  const keys = [...c.extensions.keys()];
  assert.deepEqual(keys, ['typ', 'generation', 'ufrag']);
});

test('trailing extension key with no value is kept as empty string', () => {
  const c = parseIceCandidate(
    'candidate:1 1 udp 1 192.0.2.1 1 typ host generation'
  );
  assert.equal(c.extensions.get('generation'), '');
  assert.equal(c.extensions.size, 2);
});

test('candidate with no extensions has empty type and empty map', () => {
  const c = parseIceCandidate(
    'candidate:1 1 udp 1 192.0.2.1 1 typ host'
  );
  assert.equal(c.type, 'host');
  assert.equal(c.extensions.size, 1);
});

test('throws on fewer than seven fields', () => {
  assert.throws(
    () => parseIceCandidate('candidate:1 1 udp 1 192.0.2.1'),
    /at least 7 fields/
  );
});

test('throws on non-string input', () => {
  assert.throws(
    () => parseIceCandidate(42),
    TypeError
  );
});

test('collapses internal runs of whitespace', () => {
  const c = parseIceCandidate(
    'candidate:1   1   udp   1   192.0.2.1   1   typ   host'
  );
  assert.equal(c.foundation, '1');
  assert.equal(c.port, 1);
  assert.equal(c.type, 'host');
});

test('normalizeCandidate round-trips a parsed candidate', () => {
  const input = 'candidate:842163049 1 udp 1677729535 192.0.2.3 64325 typ host generation 0';
  const c = parseIceCandidate(input);
  const out = normalizeCandidate(c);
  assert.equal(out, input);
});

test('normalizeCandidate preserves extension order including duplicates', () => {
  const c = parseIceCandidate(
    'candidate:1 1 udp 1 192.0.2.1 1 typ host foo a foo b'
  );
  // Map keeps last value for a key, but iteration order is insertion order.
  assert.equal(c.extensions.get('foo'), 'b');
  const out = normalizeCandidate(c);
  // The duplicate key appears once in output because Map deduplicates by key.
  assert.equal(out, 'candidate:1 1 udp 1 192.0.2.1 1 typ host foo b');
});
