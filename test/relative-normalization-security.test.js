'use strict'

const test = require('tape')
const fastURI = require('..')

const ABSOLUTE_BASES = [
  'http://h/p/q/r',
  'http://h/',
  'foo://h/a/b/',
  'http://h/p/q/'
]

const RELATIVE_BASES = ['', 'base', 'relative/base']

test('normalize keeps the meaning of relative-path references', (t) => {
  const cases = [
    ['a/../b', 'b'],
    ['x/..', './'],
    ['../x', '../x'],
    ['./../x', '../x'],
    ['a/b/../../..', '..'],
    ['a/./b', 'a/b'],
    ['a/b/..', 'a/'],
    ['.', './'],
    ['..', '..'],
    ['../', '../'],
    ['../../a/./b/../c', '../../a/c'],
    ['a//..', 'a/'],
    ['a/../b?q#f', 'b?q#f']
  ]
  for (const [input, expected] of cases) {
    t.equal(fastURI.normalize(input), expected, `${input} -> ${expected}`)
  }
  t.end()
})

test('normalize never turns a relative-path reference into a root or network path', (t) => {
  t.equal(fastURI.normalize('.//x'), './/x', 'leading empty segment is kept behind "."')
  t.equal(fastURI.normalize('a/..//x'), './/x', 'collapsed prefix does not expose "//"')
  t.equal(fastURI.parse(fastURI.normalize('a/..//x')).host, undefined, 'no authority is introduced')
  t.equal(fastURI.normalize('./a:b'), 'a%3Ab', 'exposed colon is still escaped')
  t.equal(fastURI.parse(fastURI.normalize('./a:b')).scheme, undefined, 'no scheme is introduced')
  t.end()
})

test('normalize keeps the existing behavior for root-relative and absolute paths', (t) => {
  t.equal(fastURI.normalize('/a/../b'), '/b')
  t.equal(fastURI.normalize('/../x'), '/x')
  t.equal(fastURI.normalize('http://h/a/../../b'), 'http://h/b')
  t.end()
})

test('equal does not alias relative references with different targets', (t) => {
  t.equal(fastURI.equal('../x', 'x'), false)
  t.equal(fastURI.equal('a/../b', '/b'), false)
  t.equal(fastURI.equal('x/..', '/'), false)
  t.equal(fastURI.equal('a/../b', 'b'), true)
  t.end()
})

test('resolving a normalized relative reference matches resolving the original', (t) => {
  for (const base of [...ABSOLUTE_BASES, ...RELATIVE_BASES]) {
    for (const ref of ['a/../b', 'x/..', '../x', './../x', 'a/b/../../..', '.', '..', './/x']) {
      t.equal(
        fastURI.resolve(base, fastURI.normalize(ref)),
        fastURI.resolve(base, ref),
        `${base} + ${ref}`
      )
    }
  }
  t.equal(fastURI.resolve('http://h/p/q/r', fastURI.normalize('a/../b')), 'http://h/p/q/b')
  t.equal(fastURI.resolve('http://h/p/q/r', fastURI.normalize('../x')), 'http://h/p/x')
  t.end()
})

test('property: normalization of relative references is resolution-preserving and idempotent', (t) => {
  const segments = ['a', 'b', '.', '..', '']
  // Deterministic linear congruential generator so failures are reproducible.
  let seed = 0x5ec02
  const next = (n) => {
    seed = (seed * 1103515245 + 12345) % 2147483648
    return Math.floor((seed / 2147483648) * n)
  }

  let failures = 0
  let checked = 0
  for (let i = 0; i < 4000; i++) {
    const length = 1 + next(6)
    const parts = []
    for (let j = 0; j < length; j++) parts.push(segments[next(segments.length)])
    const ref = parts.join('/')
    // Only relative-path references: empty refs and refs starting with "/"
    // are not affected by this change ("//" would also introduce an authority).
    if (ref === '' || ref[0] === '/') continue

    checked++
    const normalized = fastURI.normalize(ref)
    if (fastURI.normalize(normalized) !== normalized) {
      failures++
      t.fail(`not idempotent: ${ref} -> ${normalized} -> ${fastURI.normalize(normalized)}`)
    }
    // 3.x's removeDotSegments (used by resolve) collapses a trailing "//" to
    // "/" (fixed in v4 by #185), so resolve() itself is inconsistent for
    // these paths regardless of normalization.
    if (normalized.endsWith('//')) continue
    for (const base of ABSOLUTE_BASES) {
      const expected = fastURI.resolve(base, ref)
      const actual = fastURI.resolve(base, normalized)
      if (actual !== expected) {
        failures++
        t.fail(`${base} + ${ref}: normalized ${normalized} resolves to ${actual}, expected ${expected}`)
      }
    }
  }

  t.ok(checked > 1000, `checked ${checked} relative references`)
  t.equal(failures, 0, 'no relative reference changed meaning')
  t.end()
})

test('suffix normalization preserves relative path meaning', (t) => {
  const options = { reference: 'suffix', scheme: 'x' }
  for (const [input, expected] of [
    ['a/../b', 'b'],
    ['x/..', './'],
    ['a/../a:b', './a:b']
  ]) {
    t.equal(fastURI.normalize(input, options), expected, `${input} -> ${expected}`)
  }
  t.end()
})

test('normalize does not promote a colon-first relative reference to a scheme (skipEscape)', (t) => {
  // RFC 3986 section 4.2: a first path segment containing ":" must stay
  // protected by a leading "./", or it is mistaken for a scheme. Collapsing
  // the protecting dot segment must not expose the colon. The default path
  // escapes the colon; with skipEscape the colon is emitted raw and the
  // reference is reparsed as absolute (scheme "a"), changing its meaning.
  const colonRefs = ['./a:b', 'a/../a:b']
  for (const ref of colonRefs) {
    const normalized = fastURI.normalize(ref, { skipEscape: true })
    t.equal(
      fastURI.parse(normalized).scheme,
      undefined,
      `${ref} -> ${normalized} must not introduce a scheme`
    )
    for (const base of ABSOLUTE_BASES) {
      t.equal(
        fastURI.resolve(base, normalized, { skipEscape: true }),
        fastURI.resolve(base, ref, { skipEscape: true }),
        `${base} + ${ref}: normalized ${normalized} must resolve the same`
      )
    }
  }
  t.end()
})

test('serialize keeps relative-path meaning when no scheme is emitted', (t) => {
  t.equal(fastURI.serialize({ path: 'a/../b' }), 'b')
  t.equal(fastURI.serialize({ path: '../x' }), '../x')
  t.equal(fastURI.serialize({ path: 'x/..' }), './')
  // An empty scheme is not emitted, so the path is still a relative reference.
  t.equal(fastURI.serialize({ scheme: '', path: 'a/../b' }), 'b')
  t.equal(fastURI.serialize({ scheme: '', path: 'x/..' }), './')
  t.end()
})

test('resolving against a relative base keeps the result relative', (t) => {
  t.equal(fastURI.resolve('', 'x/..'), './')
  t.equal(fastURI.resolve('', '../x'), '../x')
  t.equal(fastURI.resolve('base', 'a/../a:b', { skipEscape: true }), './a:b')
  t.equal(fastURI.parse(fastURI.resolve('', 'a/../a:b')).scheme, undefined, 'no scheme is introduced')
  t.equal(fastURI.serialize(fastURI.resolveComponent({ path: 'relative/base' }, { path: '../../x' })), '../x')
  t.end()
})

// A suffix reference never emits its scheme token, so it is a scheme-less
// (path-noscheme) reference: a bare ':' in its first path segment must be
// escaped, or the serialized output reparses as an absolute URI with a scheme.
// @see https://github.com/fastify/fast-uri/security/advisories/GHSA-333x-w4r6-6crp
test('suffix reference escapes a first-segment colon instead of emitting a scheme', (t) => {
  const dangerous = /^(?:javascript|data|vbscript):/i
  const options = { reference: 'suffix', scheme: 'x' }

  for (const input of ['javascript:alert(1)', '%6Aavascript:alert(1)', 'data:text/html,x', 'vbscript:msgbox(1)']) {
    t.notOk(dangerous.test(fastURI.normalize(input, options)), `${input} normalizes to an inert reference`)
  }

  t.equal(
    fastURI.normalize('javascript:alert(1)', options),
    'javascript%3Aalert%281%29',
    'escapes the leading-segment colon to %3A'
  )
  t.notOk(
    dangerous.test(fastURI.resolve('https://a.example/base/', '%6Aavascript:alert(1)', { reference: 'suffix' })),
    'resolve in suffix mode does not emit a live scheme'
  )

  // legitimate suffix usage is unchanged
  t.equal(fastURI.normalize('path/to/file', options), 'path/to/file', 'plain path unchanged')
  t.equal(fastURI.normalize('a/b:c', options), 'a/b:c', 'colon in a later segment stays literal')
  t.end()
})

test('scheme-less output without dot-segment removal cannot emit a scheme', (t) => {
  // absolutePath (and skipEscape, used by resolve()) skip the dot-segment
  // removal that would otherwise keep a colon-first segment behind "./", so
  // the path-noscheme encoding must be applied on its own.
  const dangerous = /^(?:javascript|data|vbscript):/i
  const inputs = ['javascript:alert(1)', '%6Aavascript:alert(1)', 'data:text/html,x', 'vbscript:msgbox(1)']
  const optionSets = [
    { reference: 'suffix', scheme: 'x', absolutePath: true },
    { reference: 'suffix', scheme: 'x', absolutePath: true, skipEscape: true },
    { reference: 'suffix', scheme: 'x', skipEscape: true }
  ]
  for (const options of optionSets) {
    for (const input of inputs) {
      const normalized = fastURI.normalize(input, options)
      const label = `${input} with ${JSON.stringify(options)} -> ${normalized}`
      t.notOk(dangerous.test(normalized), `${label} is inert`)
      t.equal(fastURI.parse(normalized).scheme, undefined, `${label} reparses without a scheme`)
    }
  }

  t.equal(
    fastURI.serialize({ scheme: 'x', path: 'javascript:alert(1)' }, { reference: 'suffix', absolutePath: true }),
    'javascript%3Aalert%281%29',
    'suffix serialize escapes the first-segment colon'
  )
  t.equal(
    fastURI.serialize({ path: 'javascript:alert(1)' }, { skipEscape: true, absolutePath: true }),
    'javascript%3Aalert(1)',
    'skipEscape serialize escapes the first-segment colon'
  )
  t.equal(
    fastURI.serialize({ scheme: '', path: 'javascript:alert(1)' }, { absolutePath: true }),
    'javascript%3Aalert%281%29',
    'an empty, unemitted scheme does not expose the first-segment colon'
  )
  t.equal(
    fastURI.serialize({ scheme: 'urn', nid: 'javascript', nss: 'alert(1)' }, { reference: 'suffix', absolutePath: true }),
    'javascript%3Aalert(1)',
    'a suffix URN does not emit its NID as a scheme'
  )
  for (const ref of ['javascript:alert(1)', '%6Aavascript:alert(1)']) {
    const resolved = fastURI.resolve('https://a.example/base/', ref, { reference: 'suffix', absolutePath: true })
    t.equal(resolved, 'javascript%3Aalert(1)', `suffix resolve of ${ref} escapes the first-segment colon`)
    t.equal(fastURI.parse(resolved).scheme, undefined, `suffix resolve of ${ref} reparses without a scheme`)
  }
  t.equal(
    fastURI.equal({ scheme: '', path: 'javascript:alert(1)' }, 'javascript:alert(1)', { absolutePath: true }),
    false,
    'a scheme-less reference does not compare equal to a scheme-bearing URI'
  )
  t.end()
})

test('path-noscheme encoding leaves emitted schemes, later segments and root paths alone', (t) => {
  t.equal(fastURI.normalize('x:a:b'), 'x:a:b', 'colon after an emitted scheme stays literal')
  t.equal(fastURI.serialize({ scheme: 'x', path: 'a:b/c:d' }, { absolutePath: true }), 'x:a:b/c:d')
  t.equal(fastURI.serialize({ path: 'a/b:c' }, { skipEscape: true, absolutePath: true }), 'a/b:c', 'later-segment colon stays literal')
  t.equal(fastURI.serialize({ path: '/a:b' }, { skipEscape: true, absolutePath: true }), '/a:b', 'root-relative path is unchanged')
  t.equal(fastURI.normalize('a/../a:b', { reference: 'suffix', scheme: 'x' }), './a:b', 'a "./"-protected colon stays literal')
  t.end()
})
