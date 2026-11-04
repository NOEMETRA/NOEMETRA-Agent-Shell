/**
 * native-token-store.ts
 *
 * The encrypted-at-rest persistence seam for RFC 8252 native OAuth tokens:
 * NativeTokenSet → JSON → safeStorage blob → store file, and back again on the
 * next launch.
 *
 * Kept standalone (no `import 'electron'`) so the whole restart path unit-tests
 * with the `electron` vitest project — the same pattern as native-oauth.ts.
 * main.ts owns the electron-coupled halves and injects them: the safeStorage
 * encrypt/decrypt pair and the userData store-file read/write.
 *
 * The parser direction is the load-bearing detail. What lands on disk is the
 * *normalized* camelCase NativeTokenSet, so the reload boundary is
 * parseStoredTokenSet(). Gateway `/auth/native/token` responses are snake_case
 * and stay with parseTokenResponse(); crossing the two made the decrypted set
 * throw on every launch, which surfaced as "signed out after restart" (#73271).
 */

import { type NativeTokenSet, parseStoredTokenSet } from './native-oauth'

/** One encrypted blob as written per gateway base URL. */
export interface StoredTokenSecret {
  encoding?: string
  value?: string
}

/**
 * The narrow set of side effects main.ts owns. Everything here is injected so
 * the store/load round trip can be exercised without an Electron runtime, and
 * so production keeps using safeStorage unchanged.
 */
export interface NativeTokenStoreIo {
  /**
   * Encrypt one plaintext blob. main.ts passes the strict safeStorage helper,
   * which THROWS when the OS keychain is unavailable — that must stay loud.
   * A `null` return is treated as the same authoritative failure: the caller
   * throws rather than persisting an empty entry over good tokens.
   */
  encrypt: (plaintext: string) => StoredTokenSecret | null
  /** Decrypt a stored payload; returns '' when it cannot be read. */
  decrypt: (secret: any) => string
  /** Raw store-file text. Throws when the file is absent — treated as empty. */
  readStoreText: () => string
  /** Persist the store-file text (main.ts writes mode 0600 under userData). */
  writeStoreText: (text: string) => void
  rememberLog?: (message: string) => void
}

/**
 * baseUrl → encrypted payload. A missing, unreadable, or hand-mangled store
 * reads as empty rather than throwing: a failed *read* falls to the next rung.
 *
 * Arrays are rejected alongside every other non-object shape: assigning
 * store[baseUrl] on an array would set a non-index property, which
 * JSON.stringify drops on the way back out — the write would look like it
 * succeeded and the tokens would be gone on the next launch.
 */
function readStore(io: NativeTokenStoreIo): Record<string, any> {
  try {
    const parsed = JSON.parse(io.readStoreText())

    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {}
  } catch {
    return {}
  }
}

/**
 * A gateway URL safe to write into a log line.
 *
 * normalizeRemoteBaseUrl() strips query, fragment, and trailing slashes but
 * NOT userinfo, so a configured gateway can legitimately carry
 * `user:password@` all the way down to this store. Interpolating that into a
 * failure log would spill the credentials into the desktop log file, so drop
 * the userinfo and keep only what makes the line useful — scheme, host, port,
 * path. A value URL cannot parse never falls back to the raw input: echoing it
 * is the exact leak this guards against.
 */
export function redactGatewayUrl(baseUrl: string): string {
  try {
    if (baseUrl.includes('#conn=')) {
      const [urlPart, connPart] = baseUrl.split('#conn=')
      const parsed = new URL(urlPart)

      parsed.username = ''
      parsed.password = ''

      return `${parsed.protocol}//${parsed.host}${parsed.pathname}#conn=${connPart}`
    }
    const parsed = new URL(baseUrl)

    parsed.username = ''
    parsed.password = ''

    // `host` already carries a non-default port.
    return `${parsed.protocol}//${parsed.host}${parsed.pathname}`
  } catch {
    return '<invalid gateway URL>'
  }
}

/**
 * Write (or, with `tokens === null`, drop) one gateway's token set, merging
 * into whatever other gateways are already stored.
 */
export function persistNativeTokenSet(baseUrl: string, tokens: NativeTokenSet | null, io: NativeTokenStoreIo): void {
  const store = readStore(io)

  if (tokens) {
    // Encrypt the whole set as one blob so the refresh token never lands in
    // plaintext on disk. Deliberately outside the try below: an unusable
    // keychain is an authoritative write failure and must surface to the
    // caller, not be logged away as if the tokens were saved.
    const secret = io.encrypt(JSON.stringify(tokens))

    if (!secret) {
      // A null blob is the same failure as a throw, only quieter. Storing it
      // would replace a good entry with nothing: the write would report
      // success, the next launch would show signed out, and the refresh token
      // would be unrecoverable. Fail before touching the store.
      throw new Error('Secure token storage returned no encrypted payload; refusing to overwrite stored native tokens.')
    }

    store[baseUrl] = secret
  } else {
    delete store[baseUrl]
  }

  try {
    io.writeStoreText(JSON.stringify(store))
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error)

    io.rememberLog?.(`[native-oauth] failed to persist tokens: ${detail}`)
  }
}

/**
 * Reconstruct a gateway's token set from the stored encrypted payload. Returns
 * null when nothing is stored, when the blob cannot be decrypted, or when it
 * does not parse — never a partially-populated set.
 */
export function loadNativeTokenSet(baseUrl: string, io: NativeTokenStoreIo): NativeTokenSet | null {
  // The UNREDACTED url is the store key — redaction is for logs only.
  const secret = readStore(io)[baseUrl]

  if (!secret) {
    return null
  }

  try {
    const plaintext = io.decrypt(secret)

    if (!plaintext) {
      // A keychain that is merely locked/unavailable right now must not cost
      // the user their refresh token — leave the entry for the next attempt.
      io.rememberLog?.(
        `[native-oauth] failed to decrypt stored tokens for ${redactGatewayUrl(baseUrl)}; keeping stored entry for retry`
      )

      return null
    }

    // Stored blobs are normalized camelCase sets, never raw gateway responses.
    return parseStoredTokenSet(JSON.parse(plaintext))
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error)

    io.rememberLog?.(`[native-oauth] failed to load stored tokens for ${redactGatewayUrl(baseUrl)}: ${detail}`)

    return null
  }
}

function safeNormalizeUrl(raw: unknown): string {
  try {
    let s = String(raw || '').trim()
    if (!s) return ''
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
      s = `http://${s}`
    }
    const parsed = new URL(s)
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return ''
    parsed.hash = ''
    parsed.search = ''
    parsed.pathname = parsed.pathname.replace(/\/+$/, '')
    return parsed.toString().replace(/\/+$/, '')
  } catch {
    return ''
  }
}

/**
 * Map normalized gateway URLs to their owning connection ID in the legacy registry.
 * An unscoped token can only be claimed if there was unambiguously EXACTLY ONE
 * connection configured for that URL. If multiple connections shared the URL (even
 * including the primary), the token is ambiguous and must be quarantined (apps/desktop/AGENTS.md:46-48).
 */
export function buildLegacyUrlToConnectionMap(legacyRegistry: any): Map<string, string> {
  const map = new Map<string, string>()
  if (!legacyRegistry || !Array.isArray(legacyRegistry.connections)) return map

  const byUrl = new Map<string, any[]>()
  for (const conn of legacyRegistry.connections) {
    if (conn && (conn.kind === 'remote' || conn.kind === 'cloud') && conn.url) {
      const norm = safeNormalizeUrl(conn.url)
      if (norm) {
        const list = byUrl.get(norm) || []
        list.push(conn)
        byUrl.set(norm, list)
      }
    }
  }

  for (const [norm, conns] of byUrl.entries()) {
    if (conns.length === 1 && conns[0]?.id) {
      map.set(norm, conns[0].id)
    }
  }

  return map
}

/**
 * Pure merger for native token store contents: combines legacy and current token records,
 * remapping #conn=<oldId> references to new connection IDs where applicable.
 * Active destination entries take precedence over legacy entries on key collisions.
 * Unscoped legacy tokens are scoped to their original connection from the legacy registry
 * so they cannot collide with or be appropriated by destination connections.
 * Legacy unscoped tokens whose owning connection cannot be unambiguously identified are
 * quarantined to prevent cross-account credential leakage (apps/desktop/AGENTS.md:46-48).
 */
export function mergeNativeTokenStoreObjects(
  legacyStore: Record<string, any>,
  currentStore: Record<string, any>,
  idRemap: Map<string, string> = new Map(),
  legacyUrlToConnId: Map<string, string> = new Map()
): { merged: Record<string, any>; quarantined: Record<string, any>; modified: boolean } {
  const merged: Record<string, any> = { ...currentStore }
  const quarantined: Record<string, any> = {}
  let modified = false

  for (const [key, value] of Object.entries(legacyStore)) {
    let targetKey = key
    if (key.includes('#conn=')) {
      const [urlPart, connId] = key.split('#conn=')
      const mappedId = idRemap.get(connId) || connId
      targetKey = `${urlPart}#conn=${mappedId}`
    } else {
      // Unscoped legacy key (bare URL): check if legacy registry had an unambiguous owning connection for this URL
      const normKey = safeNormalizeUrl(key)
      const legacyConnId = (normKey && legacyUrlToConnId.get(normKey)) || legacyUrlToConnId.get(key)
      if (legacyConnId) {
        const mappedId = idRemap.get(legacyConnId) || legacyConnId
        targetKey = `${normKey || key}#conn=${mappedId}`
      } else {
        // Ambiguous ownership: multiple legacy connections share this URL (or none matched).
        // Per AGENTS.md:46-48, never import ambiguous credentials into the active unscoped store
        // where another connection could claim them. Quarantine them for recovery instead.
        quarantined[key] = value
        continue
      }
    }
    if (!merged[targetKey]) {
      merged[targetKey] = value
      modified = true
    }
  }

  return { merged, quarantined, modified }
}
