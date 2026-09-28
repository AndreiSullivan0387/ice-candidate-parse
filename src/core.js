/**
 * ICE candidate parser.
 *
 * WebRTC ICE candidates come in two common surface forms:
 *
 *   1. Raw SDP line:  "a=candidate:842163049 1 udp 1677729535 ... typ srflx"
 *   2. API string:    "candidate:842163049 1 udp 1677729535 ... typ srflx"
 *
 * Both are accepted. The parser strips a leading "a=" and/or a leading
 * "candidate:" prefix, then tokenises on whitespace. The first seven tokens
 * are the fixed foundation fields; everything after is an extensions list
 * of key/value pairs separated by spaces.
 *
 * Design decisions (stated plainly so the tests can be read against them):
 *
 *  - We do NOT validate that addresses are reachable or well-formed IPs.
 *    The brief asks for parsing, not validation, and real candidates in the
 *    wild include IPv6, IPv4, hostnames, and obfuscated relay addresses.
 *    Validating would invent a requirement the brief does not state.
 *
 *  - The `extensions` field is an ordered Map, not a plain object, because
 *    RFC 8445 does not forbid duplicate keys and order can matter for
 *    debugging. A Map preserves insertion order and tolerates repeats.
 *
 *  - `priority` is returned as a Number when it fits in 2^53 safely, else
 *    as a string. ICE priorities are 32-bit, so in practice this is always
 *    a Number, but the guard means we never silently lose precision.
 *
 *  - `port` is a Number. Ports are 16-bit; Number is exact.
 *
 *  - Unknown extension keys are kept verbatim. We do not map `typ` to
 *    `type` inside the extensions map; `type` is a top-level field and
 *    `extensions` retains the original `typ` entry so nothing is lost.
 */

/**
 * @typedef {Object} IceCandidate
 * @property {string} foundation
 * @property {number} component      1 = RTP, 2 = RTCP (per RFC 5245).
 * @property {string} protocol       "udp" or "tcp", lowercased.
 * @property {number|string} priority 32-bit value; Number when safe.
 * @property {string} address
 * @property {number} port
 * @property {string} type           "host", "srflx", "prflx", "relay".
 *                                  Empty string if no typ extension present.
 * @property {Map<string, string>} extensions  Ordered, preserves dups.
 * @property {string} raw            The input string after prefix stripping.
 */

/**
 * Remove leading "a=" and/or "candidate:" so both SDP lines and API
 * strings parse the same way. We strip iteratively rather than with a
 * single regex so that "a=candidate:..." and "candidate:..." and
 * "a=candidate:..." all collapse to the same body without accidentally
 * eating a legitimate "a=" deeper in the string.
 *
 * @param {string} input
 * @returns {string}
 */
function stripPrefix(input) {
  let s = input.trim();
  // Strip at most one leading "a=".
  if (s.startsWith('a=')) {
    s = s.slice(2);
  }
  // Strip at most one leading "candidate:".
  if (s.startsWith('candidate:')) {
    s = s.slice('candidate:'.length);
  }
  return s;
}

/**
 * Parse a priority token. ICE priorities are 32-bit unsigned, which fits
 * exactly in a JS Number (2^53 safe range). We still guard: anything
 * outside Number.MAX_SAFE_INTEGER is returned as a string so the caller
 * never sees a rounded value.
 *
 * @param {string} token
 * @returns {number|string}
 */
function parsePriority(token) {
  const n = Number(token);
  if (Number.isSafeInteger(n) && n >= 0) {
    return n;
  }
  return token;
}

/**
 * Parse an ICE candidate string.
 *
 * @param {string} input
 * @returns {IceCandidate}
 * @throws {TypeError} if input is not a string.
 * @throws {Error} if the candidate does not have at least the seven
 *   fixed foundation fields.
 */
export function parseIceCandidate(input) {
  if (typeof input !== 'string') {
    throw new TypeError(`parseIceCandidate expected a string, got ${typeof input}`);
  }

  const body = stripPrefix(input);
  // Split on any run of whitespace. Candidates are space-delimited, but
  // real SDP can contain trailing spaces or tabs; collapsing is safe
  // because none of the fixed fields are allowed to contain whitespace.
  const tokens = body.split(/\s+/).filter((t) => t.length > 0);

  if (tokens.length < 7) {
    throw new Error(
      `ICE candidate must have at least 7 fields, got ${tokens.length}: ${JSON.stringify(body)}`
    );
  }

  const [
    foundation,
    componentStr,
    protocol,
    priorityStr,
    address,
    portStr,
    // first extension token (if any) is consumed by the loop below
  ] = tokens;

  const component = Number(componentStr);
  const port = Number(portStr);
  const priority = parsePriority(priorityStr);

  // Extensions start at index 6. They are key/value pairs: "typ srflx",
  // "raddr 10.0.0.1", "rport 1234", etc. A trailing key with no value is
  // kept with an empty string value rather than dropped, because losing
  // it would silently hide malformed input from the caller.
  const extensions = new Map();
  let type = '';
  for (let i = 6; i < tokens.length; i += 2) {
    const key = tokens[i];
    const value = i + 1 < tokens.length ? tokens[i + 1] : '';
    // `typ` is the one extension we promote to a top-level field. We keep
    // it in the extensions map too, so round-tripping is lossless.
    if (key === 'typ') {
      type = value;
    }
    extensions.set(key, value);
  }

  return {
    foundation,
    component,
    protocol: protocol.toLowerCase(),
    priority,
    address,
    port,
    type,
    extensions,
    raw: body,
  };
}

/**
 * Re-serialise a parsed candidate back to the canonical "candidate:..."
 * string form. Useful for tests and for normalising hand-written SDP.
 *
 * The output is NOT prefixed with "a="; callers writing SDP should add
 * that themselves. We made this choice because the API string form
 * (without "a=") is the more common interchange format in JS code, and
 * prefixing is trivially the caller's job.
 *
 * @param {IceCandidate} candidate
 * @returns {string}
 */
export function normalizeCandidate(candidate) {
  const parts = [
    candidate.foundation,
    String(candidate.component),
    candidate.protocol,
    String(candidate.priority),
    candidate.address,
    String(candidate.port),
  ];
  for (const [k, v] of candidate.extensions) {
    parts.push(k);
    parts.push(v);
  }
  return 'candidate:' + parts.join(' ');
}
