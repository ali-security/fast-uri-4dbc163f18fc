'use strict'

const { normalizeIPv6, removeDotSegments, removeDotSegmentsRelative, escapeFirstSegmentColon, recomposeAuthority, normalizePercentEncoding, normalizePathEncoding, escapePreservingEscapes, reescapeHostDelimiters, isIPv4, nonSimpleDomain } = require('./lib/utils')
const { SCHEMES, getSchemeHandler } = require('./lib/schemes')

const VALID_SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*$/u
const MALFORMED_SCHEME_ERROR = 'URI scheme is malformed.'
const MALFORMED_HOST_ERROR = 'URI host is malformed.'
// ASCII characters outside the RFC 3986 reg-name set (unreserved, sub-delims
// and "%" for pct-encoded): C0 controls, space, DEL, and "#/:<>?@[\]^`{|}.
const FORBIDDEN_DOMAIN_HOST_CHARACTER = /[\0-\x20"#/:<>?@[\\\]^`{|}\x7F]/u

/**
 * RFC 3986 section 3.1 does not allow percent-encoding in a scheme, so the
 * scheme is validated as-is and never decoded. Decoding would let inert input
 * such as `%6Aavascript:` become a live `javascript:` scheme.
 *
 * @param {string} scheme
 * @returns {string}
 */
function validateScheme (scheme) {
  const stringScheme = String(scheme)
  if (!VALID_SCHEME.test(stringScheme)) {
    throw new TypeError(MALFORMED_SCHEME_ERROR)
  }
  return stringScheme
}

/**
 * @template {import('./types/index').URIComponent|string} T
 * @param {T} uri
 * @param {import('./types/index').Options} [options]
 * @returns {T}
 */
function normalize (uri, options) {
  if (typeof uri === 'string') {
    uri = /** @type {T} */ (normalizeString(uri, options))
  } else if (typeof uri === 'object') {
    uri = /** @type {T} */ (parse(serialize(uri, options), options))
  }
  return uri
}

/**
 * @param {string} baseURI
 * @param {string} relativeURI
 * @param {import('./types/index').Options} [options]
 * @returns {string}
 */
function resolve (baseURI, relativeURI, options) {
  const schemelessOptions = options ? Object.assign({ scheme: 'null' }, options) : { scheme: 'null' }
  const baseResult = parseWithStatus(baseURI, schemelessOptions)
  const relativeResult = parseWithStatus(relativeURI, schemelessOptions)
  if (baseResult.malformedIPLiteral || relativeResult.malformedIPLiteral) {
    throw new Error('URI host is malformed.')
  }
  if (
    baseResult.malformedAuthorityOrPort ||
    relativeResult.malformedAuthorityOrPort ||
    baseResult.malformedHost ||
    relativeResult.malformedHost ||
    baseResult.malformedScheme ||
    relativeResult.malformedScheme
  ) {
    throw new Error(baseResult.parsed.error || relativeResult.parsed.error || 'URI is malformed.')
  }
  const resolved = resolveComponent(baseResult.parsed, relativeResult.parsed, schemelessOptions, true)
  const resolvedSchemeHandler = getSchemeHandler((options && options.scheme) || resolved.scheme)
  const resolvedHost = resolved.host
  const resolvedHostIsIP = resolvedHost !== undefined && resolvedHost !== '' &&
    (isIPv4(resolvedHost) || normalizeIPv6(resolvedHost).isIPV6)
  // Inputs are parsed scheme-neutrally, so delimiters and controls in a domain
  // host are only detected here, once the final scheme is known. They always
  // fail closed, including in percent-encoded hosts.
  if (hasForbiddenDomainHost(resolved, options || {}, resolvedSchemeHandler, resolvedHostIsIP)) {
    throw new Error(MALFORMED_HOST_ERROR)
  }
  canonicalizeHost(resolved, options || {}, resolvedSchemeHandler, resolvedHostIsIP)
  // Percent escapes in an ASCII reg-name are encoded data. The WHATWG hostname
  // parser can reject them even though fast-uri preserves them safely as RFC
  // 3986 data. A raw non-ASCII host must still fail closed if conversion fails.
  const encodedASCIIHost = resolvedHost && resolvedHost.indexOf('%') !== -1 &&
    !/\P{ASCII}/u.test(resolvedHost)
  if (resolved.error && !encodedASCIIHost) {
    throw new Error(resolved.error)
  }
  schemelessOptions.skipEscape = true
  return serialize(resolved, schemelessOptions)
}

/**
 * @param {import ('./types/index').URIComponent} base
 * @param {import ('./types/index').URIComponent} relative
 * @param {import('./types/index').Options} [options]
 * @param {boolean} [skipNormalization=false]
 * @returns {import ('./types/index').URIComponent}
 */
function resolveComponent (base, relative, options, skipNormalization) {
  /** @type {import('./types/index').URIComponent} */
  const target = {}
  if (!skipNormalization) {
    base = parse(serialize(base, options), options) // normalize base component
    relative = parse(serialize(relative, options), options) // normalize relative component
  }
  options = options || {}

  if (!options.tolerant && relative.scheme) {
    target.scheme = relative.scheme
    // target.authority = relative.authority;
    target.userinfo = relative.userinfo
    target.host = relative.host
    target.port = relative.port
    target.path = removeDotSegments(relative.path || '')
    target.query = relative.query
  } else {
    if (relative.userinfo !== undefined || relative.host !== undefined || relative.port !== undefined) {
      // target.authority = relative.authority;
      target.userinfo = relative.userinfo
      target.host = relative.host
      target.port = relative.port
      target.path = removeDotSegments(relative.path || '')
      target.query = relative.query
    } else {
      if (!relative.path) {
        target.path = base.path
        if (relative.query !== undefined) {
          target.query = relative.query
        } else {
          target.query = base.query
        }
      } else {
        if (relative.path[0] === '/') {
          target.path = removeDotSegments(relative.path)
        } else {
          const baseHasAuthority = base.userinfo !== undefined || base.host !== undefined || base.port !== undefined
          if (baseHasAuthority && !base.path) {
            target.path = '/' + relative.path
          } else if (!base.path) {
            target.path = relative.path
          } else {
            target.path = base.path.slice(0, base.path.lastIndexOf('/') + 1) + relative.path
          }
          target.path = !base.scheme && !baseHasAuthority && target.path[0] !== '/'
            ? removeDotSegmentsRelative(target.path)
            : removeDotSegments(target.path)
        }
        target.query = relative.query
      }
      // target.authority = base.authority;
      target.userinfo = base.userinfo
      target.host = base.host
      target.port = base.port
    }
    target.scheme = base.scheme
  }

  target.fragment = relative.fragment

  return target
}

/**
 * @param {import ('./types/index').URIComponent|string} uriA
 * @param {import ('./types/index').URIComponent|string} uriB
 * @param {import ('./types/index').Options} options
 * @returns {boolean}
 */
function equal (uriA, uriB, options) {
  const normalizedA = normalizeComparableURI(uriA, options)
  const normalizedB = normalizeComparableURI(uriB, options)

  return normalizedA !== undefined && normalizedB !== undefined && normalizedA.toLowerCase() === normalizedB.toLowerCase()
}

/**
 * @param {Readonly<import('./types/index').URIComponent>} cmpts
 * @param {import('./types/index').Options} [opts]
 * @returns {string}
 */
function serialize (cmpts, opts) {
  const component = {
    host: cmpts.host,
    scheme: cmpts.scheme,
    userinfo: cmpts.userinfo,
    port: cmpts.port,
    path: cmpts.path,
    query: cmpts.query,
    nid: cmpts.nid,
    nss: cmpts.nss,
    uuid: cmpts.uuid,
    fragment: cmpts.fragment,
    reference: cmpts.reference,
    resourceName: cmpts.resourceName,
    secure: cmpts.secure,
    error: ''
  }
  const options = Object.assign({}, opts)
  const uriTokens = []

  if (component.scheme) {
    component.scheme = validateScheme(component.scheme)
  }

  // find scheme handler
  const schemeHandler = getSchemeHandler(options.scheme || component.scheme)

  // perform scheme specific serialization
  if (schemeHandler && schemeHandler.serialize) schemeHandler.serialize(component, options)

  const hasAuthority = component.userinfo !== undefined || component.host !== undefined || component.port !== undefined
  // A reference with no emitted scheme is path-noscheme: a bare ':' in its
  // first path segment would reparse as a scheme (RFC 3986 3.3/4.2). A suffix
  // reference never emits its scheme token, so it is path-noscheme as well.
  const pathNoScheme = !options.skipEscape && (!component.scheme || options.reference === 'suffix') && !hasAuthority

  if (component.path !== undefined) {
    if (!options.skipEscape) {
      component.path = escapePreservingEscapes(component.path)

      if (component.scheme !== undefined) {
        component.path = component.path.split('%3A').join(':')
      }
      if (pathNoScheme) {
        component.path = escapeFirstSegmentColon(component.path)
      }
    } else {
      component.path = normalizePercentEncoding(component.path)
    }
  }

  if (options.reference !== 'suffix' && component.scheme) {
    // Scheme handlers may replace the scheme during serialization.
    component.scheme = validateScheme(component.scheme)
    uriTokens.push(component.scheme, ':')
  }

  const authority = recomposeAuthority(component)
  if (authority !== undefined) {
    if (options.reference !== 'suffix') {
      uriTokens.push('//')
    }

    uriTokens.push(authority)

    if (component.path && component.path[0] !== '/') {
      uriTokens.push('/')
    }
  }
  // A reference with no emitted scheme and no authority is a relative-path
  // reference: dot-segment removal must not change what it resolves to, and
  // its path is path-noscheme. That is enforced under skipEscape too
  // (resolve()), so the reapply below gates on this flag.
  const schemelessReference = (!component.scheme || options.reference === 'suffix') && authority === undefined
  if (component.path !== undefined) {
    let s = component.path

    if (!options.absolutePath && (!schemeHandler || !schemeHandler.absolutePath)) {
      // A relative-path reference keeps its unresolvable leading ".." segments
      // and must never become root-relative (RFC 3986 section 5.2.4 applies to
      // merged target paths, not to the reference itself).
      s = schemelessReference && s[0] !== '/'
        ? removeDotSegmentsRelative(s)
        : removeDotSegments(s)
    }

    // Dot-segment removal can expose a colon that was not originally in the
    // first segment, and skipEscape or absolutePath can leave one raw. Reapply
    // path-noscheme encoding so the serialized relative reference cannot be
    // reparsed as a URI scheme.
    if (schemelessReference) {
      s = escapeFirstSegmentColon(s)
    }

    if (
      authority === undefined &&
      s[0] === '/' &&
      s[1] === '/'
    ) {
      // don't allow the path to start with "//"
      s = '/%2F' + s.slice(2)
    }

    uriTokens.push(s)
  }

  if (component.query !== undefined) {
    uriTokens.push('?', component.query)
  }

  if (component.fragment !== undefined) {
    uriTokens.push('#', component.fragment)
  }
  return uriTokens.join('')
}

const URI_PARSE = /^(?:([^#/:?]+):)?(?:\/\/((?:([^#/?@]*)@)?(\[[^#/?\]]+\]|[^#/:?]*)(?::(\d*))?))?([^#?]*)(?:\?([^#]*))?(?:#((?:.|[\n\r])*))?/u

// Captures the authority component (between "//" and the next "/", "?" or "#"),
// with or without a scheme prefix, for the literal-backslash rejection below.
const AUTHORITY_PREFIX = /^(?:[^#/:?]+:)?\/\/([^/?#]*)/

// Captures the leading authority-introducer region after an optional scheme: a
// run of forward slashes, backslashes, and the characters the WHATWG URL parser
// removes before parsing (TAB U+0009, LF U+000A, CR U+000D). A valid introducer
// is exactly "//". Node treats "\" as "/" on special schemes and strips those
// characters first, so forms like "\\", "/\", "\/", "/<TAB>/", or a leading
// "<TAB>//" reach an authority in Node while fast-uri's URI_PARSE folds them into
// the path group (host confusion / SSRF / redirect bypass).
const AUTHORITY_INTRODUCER_REGION = /^(?:[^#/:?]+:)?([/\\\t\n\r]*)/

/**
 * @param {import('./types/index').URIComponent} parsed
 * @param {RegExpMatchArray} matches
 * @returns {string|undefined}
 */
function getParseError (parsed, matches) {
  if (matches[2] !== undefined && parsed.path && parsed.path[0] !== '/') {
    return 'URI path must start with "/" when authority is present.'
  }

  if (typeof parsed.port === 'number' && (parsed.port < 0 || parsed.port > 65535)) {
    return 'URI port is malformed.'
  }

  return undefined
}

/**
 * @param {import('./types/index').URIComponent} parsed
 * @param {import('./types/index').Options} options
 * @param {{ domainHost?: boolean, unicodeSupport?: boolean }|undefined} schemeHandler
 * @param {boolean} isIP
 * @returns {boolean} whether host conversion failed
 */
function canonicalizeHost (parsed, options, schemeHandler, isIP) {
  if (hasForbiddenDomainHost(parsed, options, schemeHandler, isIP)) {
    parsed.error = parsed.error || MALFORMED_HOST_ERROR
    return true
  }

  if (
    !options.unicodeSupport &&
    (!schemeHandler || !schemeHandler.unicodeSupport) &&
    parsed.host &&
    // A bracketed IP literal (RFC 3986 `IP-literal`) is never a reg-name, so it
    // must not be handed to the WHATWG hostname parser. An unterminated "[" is
    // not a literal and is still validated as a reg-name below.
    !isIPLiteral(parsed.host) &&
    (options.domainHost || (schemeHandler && schemeHandler.domainHost)) &&
    isIP === false &&
    nonSimpleDomain(parsed.host)
  ) {
    let url
    try {
      url = new URL('http://' + parsed.host)
    } catch (e) {
      parsed.error = parsed.error || "Host's domain name can not be converted to ASCII: " + e
      return true
    }
    // The WHATWG parser must have read the whole input as a host. Anything
    // else means it found a delimiter fast-uri did not, so its hostname would
    // describe a different authority.
    if (!isHostOnlyURL(url)) {
      parsed.error = parsed.error || MALFORMED_HOST_ERROR
      return true
    }
    parsed.host = url.hostname
  }
  return false
}

/**
 * Whether a domain host contains an ASCII character that RFC 3986 does not
 * allow in a reg-name (unreserved, sub-delims, or pct-encoded). Such a host is
 * rejected instead of being handed to the WHATWG URL parser, which would treat
 * "@" as a userinfo delimiter (silently dropping the data before it) and strip
 * TAB, LF, and CR. Non-ASCII characters remain allowed for IDNs.
 *
 * @param {import('./types/index').URIComponent} parsed
 * @param {import('./types/index').Options} options
 * @param {{ domainHost?: boolean }|undefined} schemeHandler
 * @param {boolean} isIP
 * @returns {boolean}
 */
function hasForbiddenDomainHost (parsed, options, schemeHandler, isIP) {
  return Boolean(
    parsed.host &&
    isIP === false &&
    !isIPLiteral(parsed.host) &&
    (options.domainHost || (schemeHandler && schemeHandler.domainHost)) &&
    FORBIDDEN_DOMAIN_HOST_CHARACTER.test(parsed.host)
  )
}

/**
 * @param {URL} url
 * @returns {boolean}
 */
function isHostOnlyURL (url) {
  return url.username === '' &&
    url.password === '' &&
    url.port === '' &&
    url.pathname === '/' &&
    url.search === '' &&
    url.hash === '' &&
    url.hostname !== ''
}

/**
 * @param {string} host
 * @returns {boolean}
 */
function isIPLiteral (host) {
  return host[0] === '[' && host[host.length - 1] === ']'
}

/**
 * @param {string} uri
 * @param {import('./types/index').Options} [opts]
 * @returns {{ parsed: import('./types/index').URIComponent, malformedAuthorityOrPort: boolean, malformedIPLiteral: boolean, malformedHost: boolean, malformedScheme: boolean }}
 */
function parseWithStatus (uri, opts) {
  const options = Object.assign({}, opts)
  /** @type {import('./types/index').URIComponent} */
  const parsed = {
    scheme: undefined,
    userinfo: undefined,
    host: '',
    port: undefined,
    path: '',
    query: undefined,
    fragment: undefined
  }

  let malformedAuthorityOrPort = false
  let malformedIPLiteral = false
  let malformedHost = false
  let malformedScheme = false

  let isIP = false
  if (options.reference === 'suffix') {
    if (options.scheme) {
      uri = options.scheme + ':' + uri
    } else {
      uri = '//' + uri
    }
  }

  // A literal backslash (U+005C) is not a valid RFC 3986 URI character and is
  // not an authority delimiter. Reject it in the authority rather than
  // rewriting it: normalizing "\" -> "/" (WHATWG error recovery) could silently
  // change the resource identified by an otherwise-invalid input, and lets "\"
  // act as a host delimiter here while Node's native URL parses a different
  // host (SSRF / redirect / origin-allowlist bypass). Percent-encoded %5C is
  // untouched and remains valid encoded data.
  const authorityMatch = uri.match(AUTHORITY_PREFIX)
  if (authorityMatch !== null && authorityMatch[1].indexOf('\\') !== -1) {
    parsed.error = 'URI authority must not contain a literal backslash.'
    malformedAuthorityOrPort = true
  }

  // Reject a malformed or whitespace-smuggled authority introducer. fast-uri
  // only recognizes a literal "//"; anything else in the leading separator run
  // (a backslash, or a "//" that appears only after removing the TAB/LF/CR that
  // Node strips) means the authority fast-uri parses differs from the one Node's
  // URL resolves. Reject rather than rewrite, mirroring the literal-backslash
  // guard above. Percent-encoded forms (%5C, %09) are untouched, valid data.
  const introducerMatch = uri.match(AUTHORITY_INTRODUCER_REGION)
  if (introducerMatch !== null) {
    const region = introducerMatch[1]
    const normalizedRegion = region.replace(/[\t\n\r]/g, '')
    // Two or more leading separators introduce an authority.
    if (normalizedRegion.length >= 2) {
      if (normalizedRegion.slice(0, 2) !== '//') {
        parsed.error = parsed.error || 'URI authority must not contain a literal backslash.'
        malformedAuthorityOrPort = true
      } else if (region.length !== normalizedRegion.length) {
        parsed.error = parsed.error || 'URI authority introducer must not contain whitespace.'
        malformedAuthorityOrPort = true
      }
    }
  }

  const matches = uri.match(URI_PARSE)

  if (matches) {
    // store each component
    parsed.scheme = matches[1]
    parsed.userinfo = matches[3]
    parsed.host = matches[4]
    parsed.port = parseInt(matches[5], 10)
    parsed.path = matches[6] || ''
    parsed.query = matches[7]
    parsed.fragment = matches[8]

    // The scheme is decoded before anything else consumes it: the scheme
    // handler is selected from it, and it is emitted verbatim by serialize().
    // Decoding it later (as an unvalidated `unescape()` during normalization)
    // let an escaped "//", ":" or CRLF re-enter the URI as live syntax, turning
    // "%2f%2fevil.example:/pwn" into a protocol-relative authority and
    // "%0d%0aSet-Cookie:..." into a header injection. Reject anything that does
    // not decode to an RFC 3986 scheme instead of rewriting it, and only
    // case-normalize a scheme that has already been validated -- lowercasing
    // first would fold non-ASCII look-alikes (e.g. U+212A KELVIN SIGN) onto
    // ASCII scheme names.
    if (parsed.scheme !== undefined) {
      if (VALID_SCHEME.test(parsed.scheme)) {
        parsed.scheme = parsed.scheme.toLowerCase()
      } else {
        parsed.error = parsed.error || MALFORMED_SCHEME_ERROR
        malformedScheme = true
      }
    }

    // fix port number
    if (isNaN(parsed.port)) {
      parsed.port = matches[5]
    }

    const parseError = getParseError(parsed, matches)
    if (parseError !== undefined) {
      parsed.error = parsed.error || parseError
      malformedAuthorityOrPort = true
    }

    if (parsed.host) {
      const ipv4result = isIPv4(parsed.host)
      if (ipv4result === false) {
        const bracketedIPLiteral = isIPLiteral(parsed.host)
        const hasIPLiteralBracket = parsed.host.indexOf('[') !== -1 || parsed.host.indexOf(']') !== -1
        const ipv6result = normalizeIPv6(parsed.host)
        isIP = ipv6result.isIPV6 || ipv6result.isIPVFuture === true
        malformedIPLiteral = (hasIPLiteralBracket && !bracketedIPLiteral) || (bracketedIPLiteral && ipv6result.error === true)
        parsed.host = isIP ? ipv6result.host : ipv6result.host.toLowerCase()

        if (malformedIPLiteral) {
          parsed.error = parsed.error || MALFORMED_HOST_ERROR
          malformedAuthorityOrPort = true
        }
      } else {
        isIP = true
      }
    }
    if (parsed.scheme === undefined && parsed.userinfo === undefined && parsed.host === undefined && parsed.port === undefined && parsed.query === undefined && !parsed.path) {
      parsed.reference = 'same-document'
    } else if (parsed.scheme === undefined) {
      parsed.reference = 'relative'
    } else if (parsed.fragment === undefined) {
      parsed.reference = 'absolute'
    } else {
      parsed.reference = 'uri'
    }

    // check for reference errors
    if (options.reference && options.reference !== 'suffix' && options.reference !== parsed.reference) {
      parsed.error = parsed.error || 'URI is not a ' + options.reference + ' reference.'
    }

    // find scheme handler
    const schemeHandler = getSchemeHandler(options.scheme || parsed.scheme)

    // convert Unicode IDN -> ASCII IDN when the effective scheme uses domain hosts
    // (a malformed IP-literal host is left as-is so it is not rewritten)
    if (!malformedIPLiteral) {
      malformedHost = canonicalizeHost(parsed, options, schemeHandler, isIP)
    }

    // An IP host was already normalized above; its only "%" is the IPv6 zone
    // separator (with any "%25" escape consumed), so it must not be decoded again.
    if (uri.indexOf('%') !== -1 && parsed.host !== undefined && !malformedIPLiteral && !isIP) {
      // Decode only current unreserved escapes, once. Using unescape() here
      // decodes every escape and lets a nested escape (e.g. %252e -> %2e -> .)
      // reparse as a live delimiter, redirecting to a different host.
      let host = normalizePercentEncoding(parsed.host, true)
      // Fold reg-name case after decoding unreserved octets. The second
      // pass only restores uppercase hex in escapes that remain encoded.
      host = normalizePercentEncoding(host.toLowerCase())
      // Resolution parses both inputs with the internal `null` scheme before
      // the effective scheme is known. Keep raw host delimiters for that step
      // so resolve() can reject them for domain-host schemes; the resolved
      // authority is encoded when it is serialized.
      parsed.host = isIP || options.scheme !== 'null' ? reescapeHostDelimiters(host, isIP) : host
    }

    if (!schemeHandler || (schemeHandler && !schemeHandler.skipNormalize)) {
      if (parsed.path) {
        parsed.path = normalizePathEncoding(parsed.path)
      }
      if (parsed.fragment) {
        try {
          parsed.fragment = encodeURI(decodeURIComponent(parsed.fragment))
        } catch {
          parsed.error = parsed.error || 'URI malformed'
        }
      }
    }

    // perform scheme specific parsing
    if (schemeHandler && schemeHandler.parse) {
      schemeHandler.parse(parsed, options)
    }
  } else {
    parsed.error = parsed.error || 'URI can not be parsed.'
  }
  return { parsed, malformedAuthorityOrPort, malformedIPLiteral, malformedHost, malformedScheme }
}

/**
 * @param {string} uri
 * @param {import('./types/index').Options} [opts]
 * @returns
 */
function parse (uri, opts) {
  return parseWithStatus(uri, opts).parsed
}

/**
 * @param {string} uri
 * @param {import('./types/index').Options} [opts]
 * @returns {string}
 */
function normalizeString (uri, opts) {
  return normalizeStringWithStatus(uri, opts).normalized
}

/**
 * @param {string} uri
 * @param {import('./types/index').Options} [opts]
 * @returns {{ normalized: string, malformedAuthorityOrPort: boolean, malformedHost: boolean, malformedScheme: boolean }}
 */
function normalizeStringWithStatus (uri, opts) {
  const { parsed, malformedAuthorityOrPort, malformedHost, malformedScheme } = parseWithStatus(uri, opts)
  return {
    normalized: malformedAuthorityOrPort || malformedHost || malformedScheme ? uri : serialize(parsed, opts),
    malformedAuthorityOrPort,
    malformedHost,
    malformedScheme
  }
}

/**
 * @param {import ('./types/index').URIComponent|string} uri
 * @param {import('./types/index').Options} [opts]
 * @returns {string|undefined}
 */
function normalizeComparableURI (uri, opts) {
  if (typeof uri === 'string') {
    const { normalized, malformedAuthorityOrPort, malformedHost, malformedScheme } = normalizeStringWithStatus(uri, opts)
    return malformedAuthorityOrPort || malformedHost || malformedScheme ? undefined : normalized
  }

  if (typeof uri === 'object') {
    try {
      return serialize(uri, opts)
    } catch {
      return undefined
    }
  }
}

const fastUri = {
  SCHEMES,
  normalize,
  resolve,
  resolveComponent,
  equal,
  serialize,
  parse
}

module.exports = fastUri
module.exports.default = fastUri
module.exports.fastUri = fastUri
