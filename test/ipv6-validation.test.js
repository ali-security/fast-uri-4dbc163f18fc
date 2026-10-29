'use strict'

const test = require('tape')
const fastURI = require('..')
const { normalizeIPv6 } = require('../lib/utils')

const HOST_ERROR = 'URI host is malformed.'

test('hosts with unbalanced or misplaced IP-literal brackets are rejected', (t) => {
  const malformed = [
    'http://[fe80',
    'http://[',
    'http://[not-an-ip',
    'http://[日本',
    'http://user@[@127.0.0.1:8123/admin',
    'http://user@]127.0.0.1:8123/admin',
    'http://user@prefix[@127.0.0.1:8123/admin',
    'http://user@prefix]@127.0.0.1:8123/admin'
  ]
  const modes = [
    ['default', undefined],
    ['Unicode', { unicodeSupport: true }]
  ]

  for (const [mode, options] of modes) {
    for (const uri of malformed) {
      const parsed = fastURI.parse(uri, options)
      const message = `${mode} mode rejects ${uri}`

      t.equal(parsed.error, HOST_ERROR, `parse ${message}`)
      t.equal(fastURI.normalize(uri, options), uri, `normalize preserves ${uri} in ${mode} mode`)
      t.equal(fastURI.equal(uri, uri, options), false, `equal ${message}`)
      t.throws(
        () => fastURI.resolve('http://example.com/', uri, options),
        /URI host is malformed\./,
        `resolve ${message}`
      )
    }
  }
  t.end()
})

const malformedLiterals = [
  '::not-valid',
  'fc00::not-hex',
  'fe80::not-hex',
  '1:2:3',
  '1:2:3:4:5:6:7',
  '1:2:3:4:5:6:7:8:9',
  '1::2::3',
  '1:::2',
  ':::1',
  '12345::',
  '1:2:3:4:5:6:7::8',
  '::ffff:192.0.2.999',
  '::ffff:192.0.2',
  '::ffff:192.168.001.1',
  '::192.0.2.1:1',
  '1:2:3:4:5:192.0.2.1::',
  'v.foo',
  'v1.',
  'v1.foo%25bar',
  'v1.K',
  'fe80::1%25',
  'fe80::1%25eth 0',
  'fe80::1%25eth%ZZ',
  'fe80::1%25K',
  'not-an-ip'
]

test('malformed bracketed IP literals fail without being rewritten', (t) => {
  for (const literal of malformedLiterals) {
    const uri = `http://[${literal}]/private`
    const parsed = fastURI.parse(uri)

    t.equal(parsed.error, HOST_ERROR, `parse rejects ${literal}`)
    t.equal(parsed.host, `[${literal.toLowerCase()}]`, `parse does not truncate ${literal}`)
    t.equal(fastURI.normalize(uri), uri, `normalize preserves ${literal}`)
    t.equal(fastURI.equal(uri, uri), false, `equal rejects ${literal}`)
  }
  t.end()
})

test('resolve throws for malformed bracketed IP literals', (t) => {
  for (const literal of malformedLiterals) {
    const uri = `http://[${literal}]/private`

    t.throws(
      () => fastURI.resolve(uri, 'child'),
      /URI host is malformed\./,
      `rejects malformed base ${literal}`
    )
    t.throws(
      () => fastURI.resolve('http://example.com/', uri),
      /URI host is malformed\./,
      `rejects malformed relative input ${literal}`
    )
  }
  t.end()
})

test('valid IPv6, IPvFuture, embedded IPv4, and zone forms normalize safely', (t) => {
  const cases = [
    ['http://[::]/', 'http://[::]/', '::'],
    ['http://[::1]/', 'http://[::1]/', '::1'],
    ['http://[1::]/', 'http://[1::]/', '1::'],
    ['http://[2001:0DB8::0001]/', 'http://[2001:db8::1]/', '2001:db8::1'],
    ['http://[0:0:0:0:0:0:0:0]/', 'http://[::]/', '::'],
    ['http://[::ffff:192.0.2.1]/', 'http://[::ffff:192.0.2.1]/', '::ffff:192.0.2.1'],
    ['http://[1:2:3:4:5:6:192.0.2.1]/', 'http://[1:2:3:4:5:6:192.0.2.1]/', '1:2:3:4:5:6:192.0.2.1'],
    ['http://[fe80::A%25EN1]/', 'http://[fe80::a%25EN1]/', 'fe80::a%EN1'],
    ['http://[fe80::a%en1]/', 'http://[fe80::a%25en1]/', 'fe80::a%en1'],
    ['http://[fe80::a%25eth%2D0]/', 'http://[fe80::a%25eth%2D0]/', 'fe80::a%eth%2D0'],
    ['http://[v1.example]/', 'http://[v1.example]/', '[v1.example]'],
    ['http://[vF.A:b]/', 'http://[vf.a:b]/', '[vf.a:b]']
  ]

  for (const [uri, normalized, host] of cases) {
    const parsed = fastURI.parse(uri)
    t.equal(parsed.error, undefined, `${uri} parses without error`)
    t.equal(parsed.host, host, `${uri} has the expected host`)
    t.equal(fastURI.normalize(uri), normalized, `${uri} normalizes safely`)
    // A well-formed IP literal must never reach the WHATWG hostname parser,
    // which would reject an IPvFuture host and make resolve() throw.
    t.doesNotThrow(() => fastURI.resolve(uri, 'child'), `${uri} resolves without throwing`)
  }
  t.end()
})

test('unterminated bracket hosts are not treated as IP literals', (t) => {
  // An unterminated "[" is not an RFC 3986 IP-literal, so it must keep being
  // rejected as a malformed host instead of being waved through as an IP address.
  const unterminated = [
    '[fe80',
    '[',
    '[not-an-ip',
    '[\u65e5\u672c',
    '::1]'
  ]

  for (const host of unterminated) {
    const result = normalizeIPv6(host)
    t.equal(result.isIPV6, false, `${host} is not an IPv6 address`)
    t.equal(result.isIPVFuture, undefined, `${host} is not an IPvFuture literal`)
    t.equal(result.error, true, `${host} is reported as malformed`)
    t.equal(result.host, host, `${host} is returned unchanged`)
  }

  for (const host of unterminated.slice(0, 4)) {
    const uri = `http://${host}`
    const parsed = fastURI.parse(uri)
    t.ok(parsed.error, `parse rejects ${uri}`)
    t.equal(fastURI.normalize(uri), uri, `normalize preserves ${uri}`)
    t.equal(fastURI.equal(uri, uri), false, `equal rejects ${uri}`)
    t.throws(
      () => fastURI.resolve(uri, 'child'),
      /URI host is malformed\./,
      `resolve rejects ${uri}`
    )
  }
  t.end()
})

test('nested bracket hosts are rejected instead of being rewritten', (t) => {
  // Before the fix the IPv6 scanner skipped every "[" and "]" byte, so a nested
  // bracket host was silently rewritten to the inner address: "http://[[fe80::1]"
  // parsed as host "fe80::1", letting an allowlisted-looking literal resolve to
  // a different address than the one a strict parser sees.
  const cases = [
    ['http://[[fe80::1]/private', '[[fe80::1]', 'fe80::1'],
    ['http://[[::1]/private', '[[::1]', '::1']
  ]

  for (const [uri, host, rewritten] of cases) {
    const parsed = fastURI.parse(uri)
    t.equal(parsed.error, HOST_ERROR, `parse rejects ${uri}`)
    t.equal(parsed.host, host, `${uri} keeps its host verbatim`)
    t.notEqual(parsed.host, rewritten, `${uri} is not rewritten to ${rewritten}`)
    t.equal(fastURI.normalize(uri), uri, `normalize preserves ${uri}`)
    t.equal(fastURI.equal(uri, uri), false, `equal rejects ${uri}`)
    t.throws(
      () => fastURI.resolve(uri, 'child'),
      /URI host is malformed\./,
      `resolve rejects ${uri}`
    )
  }
  t.end()
})
