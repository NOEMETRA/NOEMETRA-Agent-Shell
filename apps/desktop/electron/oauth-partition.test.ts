import { describe, expect, it } from 'vitest'

import { LEGACY_OAUTH_PARTITION, resolveOauthPartition } from './oauth-partition'

// #92183 — two basic-auth (cookie-flow) gateways registered in the v2
// connections registry must not share one cookie jar. Chromium cookie jars
// ignore the port, so two gateways on the same VPN host (different ports)
// evict each other's `hermes_session*` cookies when they ride the single
// shared `persist:hermes-remote-oauth` partition — and, worse, gateway A's
// cookie is silently PRESENTED to gateway B on every request. The resolver
// under test keys the jar on the registry connection's identity instead.

const registry = (primary: string, connections: any[]) => ({ primary, connections })

const remote = (id: string, url: string, extra: Record<string, unknown> = {}) => ({
  id,
  kind: 'remote',
  label: id,
  url,
  authMode: 'oauth',
  ...extra
})

describe('resolveOauthPartition (#92183 per-connection cookie jars)', () => {
  it('gives two same-host different-port registry gateways DISTINCT partitions (eviction fix)', () => {
    const reg = registry('local', [
      { id: 'local', kind: 'local' },
      remote('conn-a', 'https://10.27.27.7:9119'),
      remote('conn-b', 'https://10.27.27.7:9220')
    ])

    const a = resolveOauthPartition('https://10.27.27.7:9119', { registry: reg })
    const b = resolveOauthPartition('https://10.27.27.7:9220', { registry: reg })

    expect(a).not.toBe(LEGACY_OAUTH_PARTITION)
    expect(b).not.toBe(LEGACY_OAUTH_PARTITION)
    // Fail closed: B's requests must never ride a jar that can hold A's cookie.
    expect(a).not.toBe(b)
  })

  it('scopes a full request URL (REST/ws-ticket path) to its connection jar via longest base-url prefix', () => {
    const reg = registry('local', [
      remote('conn-a', 'https://gw.example.com'),
      remote('conn-b', 'https://gw.example.com/team-b')
    ])

    const a = resolveOauthPartition('https://gw.example.com/api/auth/ws-ticket', { registry: reg })
    const b = resolveOauthPartition('https://gw.example.com/team-b/api/auth/ws-ticket', { registry: reg })

    expect(a).not.toBe(b)
    expect(b).toContain('conn-b')
  })

  it('keeps the v1 primary remote on the LEGACY partition so upgrades do not sign the user out', () => {
    const reg = registry('mig-1', [remote('mig-1', 'https://gw-a.example.com')])

    expect(
      resolveOauthPartition('https://gw-a.example.com', {
        registry: reg,
        v1RemoteUrl: 'https://gw-a.example.com'
      })
    ).toBe(LEGACY_OAUTH_PARTITION)
  })

  it('keeps the registry PRIMARY connection on the legacy partition', () => {
    const reg = registry('conn-a', [
      remote('conn-a', 'https://gw-a.example.com'),
      remote('conn-b', 'https://gw-b.example.com')
    ])

    expect(resolveOauthPartition('https://gw-a.example.com/api/status', { registry: reg })).toBe(LEGACY_OAUTH_PARTITION)
    expect(resolveOauthPartition('https://gw-b.example.com/api/status', { registry: reg })).not.toBe(
      LEGACY_OAUTH_PARTITION
    )
  })

  it('keeps cloud connections on the legacy partition (silent portal cascade needs the shared jar)', () => {
    const reg = registry('local', [
      { id: 'cloud-1', kind: 'cloud', url: 'https://agent.nousresearch.com', authMode: 'oauth' }
    ])

    expect(resolveOauthPartition('https://agent.nousresearch.com/api/status', { registry: reg })).toBe(
      LEGACY_OAUTH_PARTITION
    )
  })

  it('keeps token-auth registry remotes on the legacy partition (no cookies involved)', () => {
    const reg = registry('local', [remote('tok-1', 'https://gw-t.example.com', { authMode: 'token' })])

    expect(resolveOauthPartition('https://gw-t.example.com', { registry: reg })).toBe(LEGACY_OAUTH_PARTITION)
  })

  it('falls back to the legacy partition for unmatched, portal, and malformed inputs', () => {
    const reg = registry('local', [remote('conn-a', 'https://gw-a.example.com')])

    expect(resolveOauthPartition('https://portal.nousresearch.com/api/agents', { registry: reg })).toBe(
      LEGACY_OAUTH_PARTITION
    )
    expect(resolveOauthPartition('not a url', { registry: reg })).toBe(LEGACY_OAUTH_PARTITION)
    expect(resolveOauthPartition('', { registry: reg })).toBe(LEGACY_OAUTH_PARTITION)
    expect(resolveOauthPartition('https://gw-a.example.com', { registry: null as any })).toBe(LEGACY_OAUTH_PARTITION)
    expect(
      resolveOauthPartition('https://gw-a.example.com', { registry: { primary: 'x', connections: 'junk' } as any })
    ).toBe(LEGACY_OAUTH_PARTITION)
  })

  it('does not treat a hostname PREFIX as a base-url match', () => {
    const reg = registry('local', [remote('conn-a', 'https://gw.example.com')])

    expect(resolveOauthPartition('https://gw.example.com.evil.tld/login', { registry: reg })).toBe(
      LEGACY_OAUTH_PARTITION
    )
  })

  it('normalizes trailing slashes and default ports when matching entry URLs', () => {
    const reg = registry('local', [remote('conn-a', 'https://gw-a.example.com:443/')])

    const got = resolveOauthPartition('https://gw-a.example.com/api/auth/ws-ticket', { registry: reg })

    expect(got).not.toBe(LEGACY_OAUTH_PARTITION)
    expect(got).toContain('conn-a')
  })

  it('produces a deterministic, partition-safe name from hostile connection ids', () => {
    const reg = registry('local', [remote('we ird/id:€', 'https://gw-a.example.com')])

    const got = resolveOauthPartition('https://gw-a.example.com', { registry: reg })

    expect(got.startsWith('persist:')).toBe(true)
    expect(got).not.toMatch(/[\s/€]/)
    expect(resolveOauthPartition('https://gw-a.example.com', { registry: reg })).toBe(got)
  })

  it('keeps the on-disk path component colon-free and %-free (Windows cookie-store regression)', () => {
    // Electron escapes ':' in a partition name to '%3A' for the folder name.
    // A Windows profile folder containing '%3A' gets a cookie store that reads
    // empty and never persists, so every cookie-auth connection would 401 and
    // re-prompt for sign-in on each dial. The partition path component must
    // therefore never need escaping, for ANY connection id.
    for (const id of ['10-0-0-88-9119', 'we ird/id:€', 'a:b/c%3Ad']) {
      const reg = registry('local', [remote(id, 'https://gw-a.example.com')])

      const pathComponent = resolveOauthPartition('https://gw-a.example.com/api/auth/ws-ticket', {
        registry: reg
      }).slice('persist:'.length)

      expect(pathComponent).not.toContain(':')
      expect(pathComponent).not.toContain('%')
    }
  })

  it('breaks same-URL ties deterministically (identical jar for identical gateway)', () => {
    const reg = registry('local', [
      remote('zeta', 'https://gw-a.example.com'),
      remote('alpha', 'https://gw-a.example.com')
    ])

    const got = resolveOauthPartition('https://gw-a.example.com', { registry: reg })

    expect(got).toContain('alpha')
  })
})

// The registry editor can sign a draft in BEFORE it is saved. The login window
// must then write to the jar the saved entry will read — an unsaved draft has
// no on-disk entry to URL-match, so identity (connectionId) decides instead.
describe('resolveOauthPartition with connectionId (pre-save sign-in identity)', () => {
  it('sends a pending (unsaved) cookie-auth remote draft to its own jar, not the legacy shared one', () => {
    const reg = registry('local', [{ id: 'local', kind: 'local' }])

    const got = resolveOauthPartition('https://macmini.lan:9119', {
      registry: reg,
      connectionId: 'macmini',
      pendingAuthMode: 'oauth',
      pendingKind: 'remote'
    })

    expect(got).not.toBe(LEGACY_OAUTH_PARTITION)
    expect(got).toContain('conn-macmini')
    // Deterministic across calls — the saved entry must read the jar the login wrote.
    expect(
      resolveOauthPartition('https://macmini.lan:9119', {
        registry: reg,
        connectionId: 'macmini',
        pendingAuthMode: 'oauth',
        pendingKind: 'remote'
      })
    ).toBe(got)
  })

  it('keeps a pending same-host sign-in out of an existing gateway’s jar (no #92183 eviction)', () => {
    const reg = registry('local', [{ id: 'local', kind: 'local' }, remote('conn-a', 'https://10.27.27.7:9119')])

    const pending = resolveOauthPartition('https://10.27.27.7:9220', {
      registry: reg,
      connectionId: 'conn-b',
      pendingAuthMode: 'oauth',
      pendingKind: 'remote'
    })

    const existing = resolveOauthPartition('https://10.27.27.7:9119', { registry: reg })

    expect(pending).not.toBe(LEGACY_OAUTH_PARTITION)
    expect(pending).not.toBe(existing)
    expect(existing).toContain('conn-a')
    expect(pending).toContain('conn-b')
  })

  it('resolves an existing entry by identity even when the URL was edited but not yet saved', () => {
    const reg = registry('local', [{ id: 'local', kind: 'local' }, remote('conn-a', 'https://old.example.com')])

    const got = resolveOauthPartition('https://new.example.com', { registry: reg, connectionId: 'conn-a' })

    expect(got).toContain('conn-a')
    expect(got).not.toBe(LEGACY_OAUTH_PARTITION)
  })

  it('keeps the primary, the local entry, cloud, and token-auth identities on the legacy jar', () => {
    const reg = registry('conn-a', [
      { id: 'local', kind: 'local' },
      remote('conn-a', 'https://gw-a.example.com'),
      remote('tok-1', 'https://gw-t.example.com', { authMode: 'token' }),
      { id: 'cloud-1', kind: 'cloud', url: 'https://agent.nousresearch.com', authMode: 'oauth' }
    ])

    expect(resolveOauthPartition('https://gw-a.example.com', { registry: reg, connectionId: 'conn-a' })).toBe(
      LEGACY_OAUTH_PARTITION
    )
    expect(resolveOauthPartition('https://gw-a.example.com', { registry: reg, connectionId: 'local' })).toBe(
      LEGACY_OAUTH_PARTITION
    )
    expect(resolveOauthPartition('https://gw-t.example.com', { registry: reg, connectionId: 'tok-1' })).toBe(
      LEGACY_OAUTH_PARTITION
    )
    expect(resolveOauthPartition('https://agent.nousresearch.com', { registry: reg, connectionId: 'cloud-1' })).toBe(
      LEGACY_OAUTH_PARTITION
    )
  })

  it('keeps a v1-migrated entry on the legacy jar even when named by id', () => {
    const reg = registry('local', [{ id: 'local', kind: 'local' }, remote('mig-1', 'https://gw-a.example.com')])

    expect(
      resolveOauthPartition('https://gw-a.example.com', {
        registry: reg,
        connectionId: 'mig-1',
        v1RemoteUrl: 'https://gw-a.example.com'
      })
    ).toBe(LEGACY_OAUTH_PARTITION)
  })

  it('ignores blank or non-string connectionIds and falls back to URL matching', () => {
    const reg = registry('local', [remote('conn-a', 'https://gw-a.example.com')])

    for (const junk of ['', '   ', 42, null, undefined]) {
      expect(resolveOauthPartition('https://gw-a.example.com', { registry: reg, connectionId: junk })).toContain(
        'conn-a'
      )
    }
  })

  // The unknown-id shortcut must grant a private jar ONLY to the draft
  // shapes that earn one after the save. Before this gate, ANY unsaved id got
  // its own jar — so a pre-save CLOUD sign-in wrote its portal session into
  // `persist:hermes-remote-oauth-conn-<id>` while the saved cloud entry kept
  // reading the shared `persist:hermes-remote-oauth` (the silent per-agent
  // cascade jar): a successful-looking sign-in that bounces straight back to
  // signed-out, plus an orphan jar. The invariant below is the contract: for
  // every draft shape, the jar the login writes equals the jar the saved
  // entry reads.
  it('pins the login-jar == saved-read-jar invariant for every draft shape', () => {
    const draftUrl = 'https://gw-draft.example.com'

    const shapes = [
      ['remote', 'oauth'],
      ['remote', 'token'],
      ['cloud', 'oauth']
    ] as const

    for (const [kind, authMode] of shapes) {
      const draftReg = registry('local', [{ id: 'local', kind: 'local' }])

      const loginJar = resolveOauthPartition(draftUrl, {
        registry: draftReg,
        connectionId: 'draft-1',
        pendingAuthMode: authMode,
        pendingKind: kind
      })

      const savedReg = registry('local', [
        { id: 'local', kind: 'local' },
        kind === 'remote' ? remote('draft-1', draftUrl, { authMode }) : { id: 'draft-1', kind, url: draftUrl, authMode }
      ])

      const readJar = resolveOauthPartition(draftUrl, { registry: savedReg })

      expect(loginJar).toBe(readJar)
    }
  })

  it('keeps a pending cloud draft on the legacy shared jar (portal cascade)', () => {
    const reg = registry('local', [{ id: 'local', kind: 'local' }])

    const got = resolveOauthPartition('https://team.hermes.cloud', {
      registry: reg,
      connectionId: 'team-cloud',
      pendingAuthMode: 'oauth',
      pendingKind: 'cloud'
    })

    expect(got).toBe(LEGACY_OAUTH_PARTITION)
  })

  it('keeps a pending token-auth remote draft on the legacy jar (no cookies)', () => {
    const reg = registry('local', [{ id: 'local', kind: 'local' }])

    const got = resolveOauthPartition('https://gw-t.example.com', {
      registry: reg,
      connectionId: 'tok-draft',
      pendingAuthMode: 'token',
      pendingKind: 'remote'
    })

    expect(got).toBe(LEGACY_OAUTH_PARTITION)
  })

  it('keeps a pending draft whose URL IS the v1 remote on the legacy jar (migration)', () => {
    const reg = registry('local', [{ id: 'local', kind: 'local' }])

    const got = resolveOauthPartition('https://gw-a.example.com', {
      registry: reg,
      connectionId: 'mig-draft',
      pendingAuthMode: 'oauth',
      pendingKind: 'remote',
      v1RemoteUrl: 'https://gw-a.example.com'
    })

    expect(got).toBe(LEGACY_OAUTH_PARTITION)
  })

  it('fails closed for an unknown-id sign-in with no pending shape: legacy jar, never a private one', () => {
    // A stale renderer can still name an id without the draft shape. The
    // resolver must never hand such a sign-in a private jar the saved entry
    // would not read — the legacy jar is the safe pre-PR behavior.
    const reg = registry('local', [{ id: 'local', kind: 'local' }])

    expect(resolveOauthPartition('https://gw.example.com', { registry: reg, connectionId: 'ghost' })).toBe(
      LEGACY_OAUTH_PARTITION
    )
  })

  it('sanitizes hostile pending ids into partition-safe names', () => {
    const reg = registry('local', [{ id: 'local', kind: 'local' }])

    const got = resolveOauthPartition('https://gw.example.com', {
      registry: reg,
      connectionId: 'we ird/id:€',
      pendingAuthMode: 'oauth',
      pendingKind: 'remote'
    })

    expect(got.startsWith('persist:')).toBe(true)
    expect(got).not.toMatch(/[\s/€]/)
  })

  it('resolves an explicit partition declared on a connection even when URL matches v1RemoteUrl (AGENTS.md:46-48)', () => {
    const reg = registry('local', [
      { id: 'local', kind: 'local' },
      {
        id: 'imported-conn',
        kind: 'remote',
        authMode: 'oauth',
        url: 'https://gw-a.example.com',
        partition: 'persist:hermes-remote-oauth-conn-imported-conn'
      }
    ])

    const byId = resolveOauthPartition('https://gw-a.example.com', {
      registry: reg,
      connectionId: 'imported-conn',
      v1RemoteUrl: 'https://gw-a.example.com'
    })
    expect(byId).toBe('persist:hermes-remote-oauth-conn-imported-conn')

    const byUrl = resolveOauthPartition('https://gw-a.example.com/api/test', {
      registry: reg,
      v1RemoteUrl: 'https://gw-a.example.com'
    })
    expect(byUrl).toBe('persist:hermes-remote-oauth-conn-imported-conn')
  })

  it('resolves an explicit partition when a migrated connection is primary (both by ID and by URL) (AGENTS.md:46-48)', () => {
    const reg = registry('imported-primary', [
      {
        id: 'imported-primary',
        kind: 'remote',
        authMode: 'oauth',
        url: 'https://gw-a.example.com',
        partition: 'persist:hermes-remote-oauth-conn-imported-primary'
      }
    ])

    const byId = resolveOauthPartition('https://gw-a.example.com', {
      registry: reg,
      connectionId: 'imported-primary'
    })
    expect(byId).toBe('persist:hermes-remote-oauth-conn-imported-primary')

    const byUrl = resolveOauthPartition('https://gw-a.example.com/api/test', {
      registry: reg
    })
    expect(byUrl).toBe('persist:hermes-remote-oauth-conn-imported-primary')
  })

  it('resolves an explicit partition for an isolated cloud connection (both by ID and by URL) (AGENTS.md:46-48, 86-91)', () => {
    const reg = registry('local', [
      { id: 'local', kind: 'local' },
      {
        id: 'cloud-isolated',
        kind: 'cloud',
        authMode: 'oauth',
        url: 'https://gateway.isolated.cloud',
        partition: 'persist:hermes-remote-oauth-conn-cloud-isolated'
      }
    ])

    const byId = resolveOauthPartition('https://gateway.isolated.cloud', {
      registry: reg,
      connectionId: 'cloud-isolated'
    })
    expect(byId).toBe('persist:hermes-remote-oauth-conn-cloud-isolated')

    const byUrl = resolveOauthPartition('https://gateway.isolated.cloud/api/test', {
      registry: reg
    })
    expect(byUrl).toBe('persist:hermes-remote-oauth-conn-cloud-isolated')

    const portalPartition = resolveOauthPartition('https://portal.nousresearch.com', {
      registry: reg,
      connectionId: 'cloud-isolated'
    })
    expect(portalPartition).toBe('persist:hermes-remote-oauth-conn-cloud-isolated')

    const defaultPortalPartition = resolveOauthPartition('https://portal.nousresearch.com', {
      registry: reg
    })
    expect(defaultPortalPartition).toBe(LEGACY_OAUTH_PARTITION)
  })

  it('keeps primary account authoritative on shared URL and scopes migrated session by connection identity (AGENTS.md:46-48)', () => {
    const reg = registry('primary-conn', [
      {
        id: 'primary-conn',
        kind: 'remote',
        authMode: 'oauth',
        url: 'https://gw.shared.example.com'
      },
      {
        id: 'migrated-conn',
        kind: 'remote',
        authMode: 'oauth',
        url: 'https://gw.shared.example.com',
        partition: 'persist:hermes-remote-oauth-conn-migrated-conn'
      }
    ])

    // Calls resolving by URL alone without connectionId belong to the primary connection (legacy partition)
    const byUrl = resolveOauthPartition('https://gw.shared.example.com/api/status', {
      registry: reg
    })
    expect(byUrl).toBe(LEGACY_OAUTH_PARTITION)

    // Calls carrying the migrated connection identity resolve to the migrated dedicated partition
    const byMigratedId = resolveOauthPartition('https://gw.shared.example.com/api/status', {
      registry: reg,
      connectionId: 'migrated-conn'
    })
    expect(byMigratedId).toBe('persist:hermes-remote-oauth-conn-migrated-conn')

    // Calls carrying primary connection identity resolve to primary's partition
    const byPrimaryId = resolveOauthPartition('https://gw.shared.example.com/api/status', {
      registry: reg,
      connectionId: 'primary-conn'
    })
    expect(byPrimaryId).toBe(LEGACY_OAUTH_PARTITION)
  })

  it('preserves longest-prefix matching for secondary OAuth connections when primary is a prefix (AGENTS.md:46-48)', () => {
    const reg = registry('primary-host', [
      {
        id: 'primary-host',
        kind: 'remote',
        authMode: 'oauth',
        url: 'https://host.example.com'
      },
      {
        id: 'secondary-team',
        kind: 'remote',
        authMode: 'oauth',
        url: 'https://host.example.com/team'
      }
    ])

    // Request for secondary's sub-path must match secondary via longest-prefix matching
    const teamUrl = resolveOauthPartition('https://host.example.com/team/api/status', {
      registry: reg
    })
    expect(teamUrl).toContain('secondary-team')

    // Request for host root must match primary
    const rootUrl = resolveOauthPartition('https://host.example.com/api/status', {
      registry: reg
    })
    expect(rootUrl).toBe(LEGACY_OAUTH_PARTITION)
  })

  it('resolves explicit partition directly when passed to resolveOauthPartition', () => {
    const reg = registry('local', [
      { id: 'local', kind: 'local' },
      { id: 'cloud-iso', kind: 'cloud', url: 'https://iso.example', authMode: 'oauth', partition: 'persist:portal-iso' }
    ])

    const byId = resolveOauthPartition('https://iso.example/api/status', {
      registry: reg,
      connectionId: 'cloud-iso'
    })
    expect(byId).toBe('persist:portal-iso')

    const byUrl = resolveOauthPartition('https://iso.example/api/status', {
      registry: reg
    })
    expect(byUrl).toBe('persist:portal-iso')
  })

  it('does not inherit another connection partition when connection IDs differ and explicit partition is omitted', () => {
    const reg = registry('local', [
      { id: 'local', kind: 'local' },
      { id: 'conn-isolated', kind: 'remote', url: 'https://gateway.example', authMode: 'oauth', partition: 'persist:conn-isolated' },
      { id: 'conn-standard', kind: 'remote', url: 'https://gateway.example', authMode: 'oauth' }
    ])

    const iso = resolveOauthPartition('https://gateway.example/api/status', {
      registry: reg,
      connectionId: 'conn-isolated'
    })
    expect(iso).toBe('persist:conn-isolated')

    const standard = resolveOauthPartition('https://gateway.example/api/status', {
      registry: reg,
      connectionId: 'conn-standard'
    })
    expect(standard).not.toBe('persist:conn-isolated')
  })

  it('normalizes explicit partition names missing persist: prefix to persistent jars', () => {
    const reg = registry('local', [
      { id: 'local', kind: 'local' },
      { id: 'custom-part', kind: 'remote', url: 'https://gateway.example', authMode: 'oauth', partition: 'custom-partition-name' }
    ])

    const got = resolveOauthPartition('https://gateway.example/api/status', {
      registry: reg,
      connectionId: 'custom-part'
    })
    expect(got).toBe('persist:custom-partition-name')
  })
})
