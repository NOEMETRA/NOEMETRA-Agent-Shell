/**
 * Tests for electron/native-token-store.ts — the encrypted-at-rest persistence
 * seam main.ts uses for RFC 8252 native OAuth tokens.
 *
 * The regression this file exists for (#73271): tokens are persisted as a
 * normalized camelCase NativeTokenSet, but the reload path fed the freshly
 * decrypted object to parseTokenResponse(), which only understands the
 * gateway's snake_case response. It threw on every launch, so a signed-in user
 * came back signed out. The parser boundary now lives inside
 * loadNativeTokenSet(), so these tests fail if it is ever crossed again.
 *
 * "Fresh load" here means what it means after a restart: nothing survives but
 * the bytes of the store file, so every assertion below is served by
 * deserializing and decrypting that text — never by an in-memory object.
 *
 * (Wired into the vitest `electron` project via electron/**\/*.test.ts.)
 */

import assert from 'node:assert/strict'

import { test } from 'vitest'

import { type NativeTokenSet, parseStoredTokenSet, parseTokenResponse } from './native-oauth'
import { migrateV1ToRegistry } from './connection-registry'
import { buildLegacyUrlToConnectionMap, loadNativeTokenSet, mergeNativeTokenStoreObjects, type NativeTokenStoreIo, persistNativeTokenSet, redactGatewayUrl } from './native-token-store'

const GATEWAY = 'https://gw.example.com'

const TOKENS: NativeTokenSet = {
  accessToken: 'AT-live-abc123',
  refreshToken: 'RT-live-xyz789',
  expiresAt: 1_893_456_000,
  provider: 'nous',
  userId: 'u-42'
}

interface FakeDisk {
  io: NativeTokenStoreIo
  logs: string[]
  /** The store-file text as it would sit on disk; null when the file is absent. */
  fileText: () => string | null
}

/**
 * A stand-in for the userData store file plus safeStorage. Encryption is
 * base64 rather than the OS keychain — opaque-blob-in, same-plaintext-out is
 * the only property this seam depends on, and it keeps the round trip
 * observable. `initialText` models a process restart: the new "process" starts
 * with nothing but the bytes the previous one wrote.
 */
function createFakeDisk(initialText: string | null = null, overrides: Partial<NativeTokenStoreIo> = {}): FakeDisk {
  let text = initialText
  const logs: string[] = []

  const io: NativeTokenStoreIo = {
    encrypt: plaintext => ({ encoding: 'safeStorage', value: Buffer.from(plaintext, 'utf8').toString('base64') }),
    decrypt: secret =>
      secret?.encoding === 'safeStorage' ? Buffer.from(String(secret.value), 'base64').toString('utf8') : '',
    readStoreText: () => {
      if (text === null) {
        // Matches fs.readFileSync on a missing file: throws, not empty string.
        throw Object.assign(new Error('ENOENT: no such file or directory'), { code: 'ENOENT' })
      }

      return text
    },
    writeStoreText: next => {
      text = next
    },
    rememberLog: message => logs.push(message),
    ...overrides
  }

  return { io, logs, fileText: () => text }
}

// --- the restart round trip ---

test('a camelCase token set survives store then a fresh load', () => {
  const first = createFakeDisk()

  persistNativeTokenSet(GATEWAY, TOKENS, first.io)

  const onDisk = first.fileText()

  assert.ok(onDisk, 'persisting must write the store file')

  // Nothing may survive the "restart" except those bytes.
  const restarted = createFakeDisk(onDisk)
  const loaded = loadNativeTokenSet(GATEWAY, restarted.io)

  assert.ok(loaded, 'a stored token set must reload after a restart')
  // Reconstructed from the payload, not handed back the object we stored.
  assert.notEqual(loaded, TOKENS)
  assert.deepEqual(loaded, TOKENS)
  assert.deepEqual(restarted.logs, [])
})

test('a fresh load restores both tokens and preserves expiry, provider and user', () => {
  const first = createFakeDisk()

  persistNativeTokenSet(GATEWAY, TOKENS, first.io)

  const loaded = loadNativeTokenSet(GATEWAY, createFakeDisk(first.fileText()).io)!

  assert.equal(loaded.accessToken, 'AT-live-abc123')
  assert.equal(loaded.refreshToken, 'RT-live-xyz789')
  // Still a number after the JSON round trip, not "1893456000".
  assert.equal(loaded.expiresAt, 1_893_456_000)
  assert.equal(typeof loaded.expiresAt, 'number')
  assert.equal(loaded.provider, 'nous')
  assert.equal(loaded.userId, 'u-42')
})

test('the loaded set is accepted by the stored-token parsing boundary', () => {
  const first = createFakeDisk()

  persistNativeTokenSet(GATEWAY, TOKENS, first.io)

  const loaded = loadNativeTokenSet(GATEWAY, createFakeDisk(first.fileText()).io)!

  // What comes back out of the store is itself a valid stored set — re-parsing
  // it is a no-op, so callers can hand it straight to the refresh path.
  assert.deepEqual(parseStoredTokenSet(loaded), loaded)
})

test('the full login-to-restart sequence keeps the two parser boundaries apart', () => {
  // Login: the gateway answers /auth/native/token in snake_case, and only
  // parseTokenResponse() understands that shape.
  const fromGateway = parseTokenResponse({
    access_token: 'AT-fresh',
    refresh_token: 'RT-fresh',
    expires_at: 1_893_456_789,
    provider: 'nous',
    user_id: 'u-77'
  })

  const first = createFakeDisk()

  persistNativeTokenSet(GATEWAY, fromGateway, first.io)

  // Restart: what was stored is normalized, so the store's own boundary reads
  // it back unchanged.
  assert.deepEqual(loadNativeTokenSet(GATEWAY, createFakeDisk(first.fileText()).io), fromGateway)
})

// --- storage hygiene ---

test('tokens are encrypted at rest, never plaintext in the store file', () => {
  const disk = createFakeDisk()

  persistNativeTokenSet(GATEWAY, TOKENS, disk.io)

  const onDisk = disk.fileText()!

  assert.doesNotMatch(onDisk, /AT-live-abc123/)
  assert.doesNotMatch(onDisk, /RT-live-xyz789/)
  assert.equal(JSON.parse(onDisk)[GATEWAY].encoding, 'safeStorage')
})

test('persisting one gateway leaves other gateways intact', () => {
  const other = 'https://other.example.com'
  const disk = createFakeDisk()

  persistNativeTokenSet(GATEWAY, TOKENS, disk.io)
  persistNativeTokenSet(other, { ...TOKENS, accessToken: 'AT-other', userId: 'u-99' }, disk.io)

  const restarted = createFakeDisk(disk.fileText())

  assert.equal(loadNativeTokenSet(GATEWAY, restarted.io)!.accessToken, 'AT-live-abc123')
  assert.equal(loadNativeTokenSet(other, restarted.io)!.accessToken, 'AT-other')
})

test('clearing removes only that gateway and reloads as signed out', () => {
  const other = 'https://other.example.com'
  const disk = createFakeDisk()

  persistNativeTokenSet(GATEWAY, TOKENS, disk.io)
  persistNativeTokenSet(other, TOKENS, disk.io)
  persistNativeTokenSet(GATEWAY, null, disk.io)

  const restarted = createFakeDisk(disk.fileText())

  assert.equal(loadNativeTokenSet(GATEWAY, restarted.io), null)
  assert.ok(loadNativeTokenSet(other, restarted.io))
})

test('an absent store file loads as signed out without logging a failure', () => {
  const disk = createFakeDisk()

  assert.equal(loadNativeTokenSet(GATEWAY, disk.io), null)
  assert.deepEqual(disk.logs, [])
})

// --- failure paths (unchanged by the extraction) ---

test('a locked keychain keeps the stored entry for a later retry', () => {
  const first = createFakeDisk()

  persistNativeTokenSet(GATEWAY, TOKENS, first.io)

  // safeStorage unavailable at load time ⇒ decryptDesktopSecret returns ''.
  const locked = createFakeDisk(first.fileText(), { decrypt: () => '' })

  assert.equal(loadNativeTokenSet(GATEWAY, locked.io), null)
  assert.match(locked.logs[0], /failed to decrypt stored tokens for https:\/\/gw\.example\.com/)
  assert.match(locked.logs[0], /keeping stored entry for retry/)
  // The refresh token must NOT be dropped just because the keychain was locked.
  assert.deepEqual(locked.fileText(), first.fileText())
})

test('a corrupt store file loads as signed out instead of throwing', () => {
  const disk = createFakeDisk('{not json')

  assert.equal(loadNativeTokenSet(GATEWAY, disk.io), null)
  assert.deepEqual(disk.logs, [])
})

test('an array store file loads as signed out instead of throwing', () => {
  const disk = createFakeDisk('[]')

  assert.equal(loadNativeTokenSet(GATEWAY, disk.io), null)
  assert.deepEqual(disk.logs, [])
})

test('an array store file is replaced by a real map rather than swallowing the write', () => {
  const disk = createFakeDisk('[]')

  persistNativeTokenSet(GATEWAY, TOKENS, disk.io)

  const written = JSON.parse(disk.fileText()!)

  // Assigning store[baseUrl] on an array sets a non-index property, which
  // JSON.stringify drops — the write would report success and the tokens would
  // be gone on the next launch.
  assert.equal(Array.isArray(written), false)
  assert.ok(written[GATEWAY], 'the gateway entry must survive serialization')
  // And it really does come back after a restart.
  assert.deepEqual(loadNativeTokenSet(GATEWAY, createFakeDisk(disk.fileText()).io), TOKENS)
})

test('a corrupt decrypted blob is reported and loads as signed out', () => {
  const disk = createFakeDisk(JSON.stringify({ [GATEWAY]: { encoding: 'safeStorage', value: 'bm90LWpzb24=' } }))

  assert.equal(loadNativeTokenSet(GATEWAY, disk.io), null)
  assert.match(disk.logs[0], /failed to load stored tokens for https:\/\/gw\.example\.com/)
})

test('a decrypted blob missing accessToken is rejected, not half-restored', () => {
  const plaintext = JSON.stringify({ refreshToken: 'RT-only', provider: 'nous' })

  const disk = createFakeDisk(
    JSON.stringify({ [GATEWAY]: { encoding: 'safeStorage', value: Buffer.from(plaintext).toString('base64') } })
  )

  assert.equal(loadNativeTokenSet(GATEWAY, disk.io), null)
  assert.match(disk.logs[0], /missing accessToken/i)
})

test('an unwritable store file is logged rather than thrown', () => {
  const disk = createFakeDisk(null, {
    writeStoreText: () => {
      throw new Error('EACCES: permission denied')
    }
  })

  assert.doesNotThrow(() => persistNativeTokenSet(GATEWAY, TOKENS, disk.io))
  assert.match(disk.logs[0], /failed to persist tokens: EACCES/)
})

test('an unusable keychain fails the write loudly and writes nothing', () => {
  const existing = createFakeDisk()

  persistNativeTokenSet(GATEWAY, TOKENS, existing.io)

  const before = existing.fileText()

  const broken = createFakeDisk(before, {
    encrypt: () => {
      throw new Error('Secure token storage is unavailable')
    }
  })

  // Storing must not pretend to succeed when the token cannot be encrypted...
  assert.throws(() => persistNativeTokenSet(GATEWAY, { ...TOKENS, accessToken: 'AT-new' }, broken.io), /unavailable/)
  // ...and must not clobber the tokens already on disk.
  assert.equal(broken.fileText(), before)
})

test('an encrypt that returns null is refused rather than blanking the stored entry', () => {
  const existing = createFakeDisk()

  persistNativeTokenSet(GATEWAY, TOKENS, existing.io)

  const before = existing.fileText()
  const nulled = createFakeDisk(before, { encrypt: () => null })
  let writes = 0

  // Spy that still delegates, so a stray write would show up in BOTH the
  // counter and the file text.
  const io = {
    ...nulled.io,
    writeStoreText: (text: string) => {
      writes += 1
      nulled.io.writeStoreText(text)
    }
  }

  // A quiet null is the same failure as a throw and must be just as loud.
  assert.throws(
    () => persistNativeTokenSet(GATEWAY, { ...TOKENS, accessToken: 'AT-new' }, io),
    /refusing to overwrite stored native tokens/
  )
  assert.equal(writes, 0, 'the store file must not be written at all')
  // Byte-for-byte unchanged...
  assert.equal(nulled.fileText(), before)
  // ...and the original token set still loads, refresh token intact.
  assert.deepEqual(loadNativeTokenSet(GATEWAY, createFakeDisk(before).io), TOKENS)
})

// --- credential redaction in logs ---
//
// normalizeRemoteBaseUrl() strips query/fragment/trailing slashes but not
// userinfo, so a configured gateway URL can carry `user:password@` into this
// store. It must stay intact as the store KEY and never reach a log line.

const CRED_GATEWAY = 'https://alice:supersecret@gw.example.com/hermes'

test('a decryption failure logs the gateway host and path but not its credentials', () => {
  const first = createFakeDisk()

  persistNativeTokenSet(CRED_GATEWAY, TOKENS, first.io)

  const before = first.fileText()
  const locked = createFakeDisk(before, { decrypt: () => '' })

  assert.equal(loadNativeTokenSet(CRED_GATEWAY, locked.io), null)
  // Still identifies which gateway failed...
  assert.match(locked.logs[0], /failed to decrypt stored tokens for https:\/\/gw\.example\.com\/hermes/)
  assert.match(locked.logs[0], /keeping stored entry for retry/)
  // ...without the userinfo.
  assert.doesNotMatch(locked.logs[0], /alice/)
  assert.doesNotMatch(locked.logs[0], /supersecret/)
  // Redaction is log-only: the entry stays under the credential-bearing key.
  assert.ok(JSON.parse(locked.fileText()!)[CRED_GATEWAY])
  assert.equal(locked.fileText(), before)
})

test('a parsing failure logs the gateway host and path but not its credentials', () => {
  const disk = createFakeDisk(JSON.stringify({ [CRED_GATEWAY]: { encoding: 'safeStorage', value: 'bm90LWpzb24=' } }))

  assert.equal(loadNativeTokenSet(CRED_GATEWAY, disk.io), null)
  assert.match(disk.logs[0], /failed to load stored tokens for https:\/\/gw\.example\.com\/hermes/)
  assert.doesNotMatch(disk.logs[0], /alice/)
  assert.doesNotMatch(disk.logs[0], /supersecret/)
})

test('the credential-bearing base URL stays the exact store key', () => {
  const first = createFakeDisk()

  persistNativeTokenSet(CRED_GATEWAY, TOKENS, first.io)

  assert.deepEqual(Object.keys(JSON.parse(first.fileText()!)), [CRED_GATEWAY])
  // The original key still round-trips a full set after a restart.
  assert.deepEqual(loadNativeTokenSet(CRED_GATEWAY, createFakeDisk(first.fileText()).io), TOKENS)
  // The redacted form is a log string, never a lookup key.
  assert.equal(loadNativeTokenSet('https://gw.example.com/hermes', createFakeDisk(first.fileText()).io), null)
})

test('an unparseable gateway URL logs a fixed placeholder rather than the raw value', () => {
  // A space makes this unparseable by URL, so redaction cannot fall back to
  // echoing the input — that would leak the very credentials it guards.
  const invalid = 'ht tp://alice:supersecret@gw.example.com'

  const disk = createFakeDisk(JSON.stringify({ [invalid]: { encoding: 'safeStorage', value: 'AAAA' } }), {
    decrypt: () => ''
  })

  assert.equal(loadNativeTokenSet(invalid, disk.io), null)
  assert.match(disk.logs[0], /<invalid gateway URL>/)
  assert.doesNotMatch(disk.logs[0], /alice/)
  assert.doesNotMatch(disk.logs[0], /supersecret/)
})

// --- token store migration & connection ID remapping ---

test('mergeNativeTokenStoreObjects preserves destination tokens on key collisions and remaps scoped keys', () => {
  const legacyStore = {
    'https://gw.example.com#conn=remote-1': { encoding: 'safeStorage', value: 'legacy-remote-1' },
    'https://gw.example.com#conn=remote-2': { encoding: 'safeStorage', value: 'legacy-remote-2' },
    'https://other.example.com#conn=conn-3': { encoding: 'safeStorage', value: 'legacy-other-3' }
  }

  const currentStore = {
    'https://gw.example.com#conn=remote-1': { encoding: 'safeStorage', value: 'active-remote-1' }
  }

  const idRemap = new Map<string, string>([
    ['remote-2', 'remote-2-imported-1'],
    ['conn-3', 'conn-3-legacy']
  ])

  const { merged, modified } = mergeNativeTokenStoreObjects(legacyStore, currentStore, idRemap)

  assert.equal(modified, true)
  // Active destination token takes precedence on collision:
  assert.equal(merged['https://gw.example.com#conn=remote-1'].value, 'active-remote-1')
  // Legacy scoped token is remapped according to connection ID reconciliation:
  assert.equal(merged['https://gw.example.com#conn=remote-2-imported-1'].value, 'legacy-remote-2')
  assert.equal(merged['https://gw.example.com#conn=remote-2'], undefined)
  assert.equal(merged['https://other.example.com#conn=conn-3-legacy'].value, 'legacy-other-3')
})

test('mergeNativeTokenStoreObjects quarantines ambiguous legacy unscoped tokens to protect account isolation', () => {
  // Two non-primary connections share the same gateway URL in legacy
  const legacyRegistry = {
    primary: 'other-conn',
    connections: [
      { id: 'other-conn', kind: 'remote', url: 'https://other.example.com' },
      { id: 'team-a', kind: 'remote', url: 'https://gw.example.com' },
      { id: 'team-b', kind: 'remote', url: 'https://gw.example.com' }
    ]
  }

  const legacyStore = {
    'https://gw.example.com': { encoding: 'safeStorage', value: 'ambiguous-team-token' }
  }

  const currentStore = {
    'https://gw.example.com#conn=dest-conn': { encoding: 'safeStorage', value: 'dest-token' }
  }

  const legacyUrlToConnId = buildLegacyUrlToConnectionMap(legacyRegistry)
  // buildLegacyUrlToConnectionMap refuses to pick an owner for ambiguous URLs:
  assert.equal(legacyUrlToConnId.get('https://gw.example.com'), undefined)

  const { merged, quarantined, modified } = mergeNativeTokenStoreObjects(
    legacyStore,
    currentStore,
    new Map(),
    legacyUrlToConnId
  )

  // Token must NOT land in the active store under bare URL:
  assert.equal(merged['https://gw.example.com'], undefined)
  // Nor under any active connection:
  assert.equal(Object.keys(merged).length, 1)
  assert.equal(merged['https://gw.example.com#conn=dest-conn'].value, 'dest-token')
  // It must be placed in quarantine for recovery:
  assert.equal(quarantined['https://gw.example.com']?.value, 'ambiguous-team-token')
})

test('mergeNativeTokenStoreObjects scopes unscoped legacy tokens to imported connection and prevents collision', () => {
  const legacyRegistry = {
    primary: 'legacy-primary',
    connections: [
      { id: 'legacy-primary', kind: 'remote', url: 'https://gw.example.com' },
      { id: 'legacy-other', kind: 'remote', url: 'https://other.example.com' }
    ]
  }

  const legacyStore = {
    'https://gw.example.com': { encoding: 'safeStorage', value: 'legacy-gw-unscoped' },
    'https://other.example.com': { encoding: 'safeStorage', value: 'legacy-other-unscoped' }
  }

  // Destination already has a connection to the same gateway with its own unscoped token
  const currentStore = {
    'https://gw.example.com': { encoding: 'safeStorage', value: 'destination-active-gw' }
  }

  const legacyUrlToConnId = buildLegacyUrlToConnectionMap(legacyRegistry)
  assert.equal(legacyUrlToConnId.get('https://gw.example.com'), 'legacy-primary')
  assert.equal(legacyUrlToConnId.get('https://other.example.com'), 'legacy-other')

  // Destination reconciled legacy-primary to legacy-primary-imported-1 because of collision
  const idRemap = new Map<string, string>([
    ['legacy-primary', 'legacy-primary-imported-1']
  ])

  const { merged, modified } = mergeNativeTokenStoreObjects(
    legacyStore,
    currentStore,
    idRemap,
    legacyUrlToConnId
  )

  assert.equal(modified, true)
  // Active destination token remains untouched:
  assert.equal(merged['https://gw.example.com'].value, 'destination-active-gw')
  // Legacy token is scoped to its imported connection rather than dropped or stealing destination's primary:
  assert.equal(merged['https://gw.example.com#conn=legacy-primary-imported-1'].value, 'legacy-gw-unscoped')
  // Other legacy token is scoped to legacy-other:
  assert.equal(merged['https://other.example.com#conn=legacy-other'].value, 'legacy-other-unscoped')
})

test('mergeNativeTokenStoreObjects preserves userinfo in gateway URLs during token key remapping', () => {
  const userinfoUrl = 'https://alice:secret@gw.example.com:8080/hermes/'
  const legacyRegistry = {
    primary: 'cred-conn',
    connections: [
      { id: 'cred-conn', kind: 'remote', url: userinfoUrl }
    ]
  }

  const legacyStore = {
    'https://alice:secret@gw.example.com:8080/hermes': { encoding: 'safeStorage', value: 'secret-tokens' }
  }

  const currentStore = {}
  const legacyUrlToConnId = buildLegacyUrlToConnectionMap(legacyRegistry)

  const idRemap = new Map<string, string>([
    ['cred-conn', 'cred-conn-imported-1']
  ])

  const { merged, modified } = mergeNativeTokenStoreObjects(
    legacyStore,
    currentStore,
    idRemap,
    legacyUrlToConnId
  )

  assert.equal(modified, true)
  // Scoped key must retain the exact user:password@ credentials matching runtime lookup:
  const expectedKey = 'https://alice:secret@gw.example.com:8080/hermes#conn=cred-conn-imported-1'
  assert.equal(merged[expectedKey]?.value, 'secret-tokens')
})

test('buildLegacyUrlToConnectionMap refuses to map URL when primary shares URL with another connection', () => {
  const legacyRegistry = {
    primary: 'primary-conn',
    connections: [
      { id: 'primary-conn', kind: 'remote', url: 'https://shared-gw.example.com' },
      { id: 'secondary-conn', kind: 'remote', url: 'https://shared-gw.example.com' }
    ]
  }

  const map = buildLegacyUrlToConnectionMap(legacyRegistry)
  // When primary shares an endpoint with another connection, ownership of an unscoped token
  // is inherently ambiguous and must NOT be attributed to the primary:
  assert.equal(map.get('https://shared-gw.example.com'), undefined)
})

test('redactGatewayUrl drops credentials while preserving scheme, host, path, and partition/connection suffix', () => {
  assert.equal(
    redactGatewayUrl('https://alice:supersecret@gw.example.com:8080/hermes'),
    'https://gw.example.com:8080/hermes'
  )
  assert.equal(
    redactGatewayUrl('https://alice:supersecret@gw.example.com:8080/hermes#conn=remote-1'),
    'https://gw.example.com:8080/hermes#conn=remote-1'
  )
  assert.equal(
    redactGatewayUrl('https://gw.example.com/api#conn=cloud-main'),
    'https://gw.example.com/api#conn=cloud-main'
  )
  assert.equal(redactGatewayUrl('invalid url string'), '<invalid gateway URL>')
})

test('buildLegacyUrlToConnectionMap resolves URL for legacy v1 connection config', () => {
  const v1Config = {
    mode: 'remote',
    remote: {
      url: 'https://v1-gw.example.com',
      authMode: 'oauth'
    }
  }

  const convertedRegistry = migrateV1ToRegistry(v1Config)
  const map = buildLegacyUrlToConnectionMap(convertedRegistry)

  assert.equal(map.get('https://v1-gw.example.com'), 'v1-gw-example-com')
})

test('mergeNativeTokenStoreObjects scopes unscoped tokens for legacy v1-only installations without quarantine', () => {
  const v1Config = {
    mode: 'remote',
    remote: {
      url: 'https://v1-gw.example.com',
      authMode: 'oauth'
    }
  }

  const convertedRegistry = migrateV1ToRegistry(v1Config)
  const legacyUrlToConnId = buildLegacyUrlToConnectionMap(convertedRegistry)

  const legacyStore = {
    'https://v1-gw.example.com': { encoding: 'safeStorage', value: 'token-bytes' }
  }
  const currentStore = {}
  const idRemap = new Map<string, string>([
    ['v1-gw-example-com', 'v1-gw-example-com-imported-1']
  ])

  const { merged, quarantined, modified } = mergeNativeTokenStoreObjects(
    legacyStore,
    currentStore,
    idRemap,
    legacyUrlToConnId
  )

  assert.equal(modified, true)
  assert.deepEqual(quarantined, {})
  assert.equal(merged['https://v1-gw.example.com#conn=v1-gw-example-com-imported-1']?.value, 'token-bytes')
})

test('buildLegacyUrlToConnectionMap handles legacy v1 config with per-profile overrides', () => {
  const v1Config = {
    mode: 'remote',
    remote: {
      url: 'https://global-gw.example.com',
      authMode: 'oauth'
    },
    profiles: {
      research: {
        mode: 'remote',
        url: 'https://research-gw.example.com',
        authMode: 'oauth'
      }
    }
  }

  const convertedRegistry = migrateV1ToRegistry(v1Config)
  const map = buildLegacyUrlToConnectionMap(convertedRegistry)

  assert.equal(map.get('https://global-gw.example.com'), 'global-gw-example-com')
  assert.equal(map.get('https://research-gw.example.com'), 'research-gw-example-com')
})


