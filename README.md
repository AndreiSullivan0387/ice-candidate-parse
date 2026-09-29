# ICE Candidate Parse

Parses WebRTC ICE candidate strings into their structured fields: foundation, component, protocol, priority, address, port, type, and an ordered extensions map.

```js
import { parseIceCandidate, normalizeCandidate } from 'ice-candidate-parse';

const c = parseIceCandidate(
  'candidate:842163049 1 udp 1677729535 192.0.2.3 64325 typ srflx raddr 192.0.2.3 rport 64325'
);
// c.foundation === '842163049'
// c.component  === 1
// c.protocol   === 'udp'
// c.priority   === 1677729535
// c.address    === '192.0.2.3'
// c.port       === 64325
// c.type       === 'srflx'
// c.extensions.get('raddr') === '192.0.2.3'
// c.extensions.get('rport') === '64325'

const line = normalizeCandidate(c); // 'candidate:842163049 1 udp ...'
```

## Why this exists

ICE candidates show up in two surface forms: raw SDP lines (`a=candidate:...`) and the strings handed to `RTCIceCandidate` (`candidate:...`). Most parsers handle one or the other. This one accepts both by stripping at most one leading `a=` and one leading `candidate:` before tokenising.

The trade-off: we do not validate addresses or ports. Real candidates include IPv6, IPv4, hostnames, and relay obfuscation tokens; validating would mean picking a schema this library does not need to own. If you want validation, do it on the parsed `address` field yourself.

## The awkward edge

Extensions are key/value pairs, but a malformed candidate can end with a lone key and no value. We keep that key with an empty-string value rather than dropping it, so callers can detect the malformation instead of having it silently swallowed. If you iterate `extensions`, expect possible empty values.

`priority` is returned as a Number when it fits in `Number.MAX_SAFE_INTEGER` (always, for 32-bit ICE priorities) and as a string otherwise. Code that compares priorities should handle both or coerce explicitly.
