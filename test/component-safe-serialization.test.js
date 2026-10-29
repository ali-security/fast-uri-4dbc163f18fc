'use strict'

const test = require('tape')
const fastURI = require('..')

test('port serialization rejects non-digit values', (t) => {
  const malformedPorts = [
    '@127.0.0.1:8124',
    '8080@evil.example',
    '8080/path',
    '8080?query',
    '8080#fragment',
    '8080:9000',
    '-1',
    '1.5',
    1.5,
    NaN,
    Infinity,
    '١'
  ]

  for (const port of malformedPorts) {
    t.throws(
      () => fastURI.serialize({ scheme: 'http', host: 'trusted.example', port, path: '/app' }),
      /URI port is malformed\./,
      String(port)
    )
  }

  t.throws(
    () => fastURI.normalize({ scheme: 'http', host: 'trusted.example', port: '@evil.example' }),
    /URI port is malformed\./,
    'object normalization rejects a malformed port'
  )
  t.equal(
    fastURI.equal(
      { scheme: 'http', host: 'trusted.example', port: '@evil.example' },
      { scheme: 'http', host: 'trusted.example', port: '@evil.example' }
    ),
    false,
    'object equality fails closed for a malformed port'
  )
  t.end()
})

test('port serialization preserves RFC 3986 digit values', (t) => {
  const validPorts = [
    [8080, '8080'],
    ['8080', '8080'],
    ['00080', '00080'],
    ['', '']
  ]

  for (const [port, expected] of validPorts) {
    t.equal(
      fastURI.serialize({ scheme: 'uri', host: 'example.test', port }),
      `uri://example.test:${expected}`,
      JSON.stringify(port)
    )
  }
  t.end()
})
