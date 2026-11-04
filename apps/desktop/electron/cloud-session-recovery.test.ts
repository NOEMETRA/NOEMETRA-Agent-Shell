import { describe, expect, it, vi } from 'vitest'

import { createCloudSessionRecovery } from './cloud-session-recovery'

const cloud = 'https://test-agent.agents.nousresearch.com'
const rejection = (statusCode = 401) => Object.assign(new Error('rejected'), { statusCode })

describe('Cloud cookie session recovery', () => {
  it('recovers an expired cookie session before minting a new ticket', async () => {
    const restore = vi.fn(async () => true)
    const run = createCloudSessionRecovery({ hasNativeSession: () => false, restoreCookieSession: restore })
    const mint = vi.fn().mockRejectedValueOnce(rejection()).mockResolvedValueOnce('fresh-ticket')
    expect(await run(cloud, mint)).toBe('fresh-ticket')
    expect(restore).toHaveBeenCalledWith(cloud, undefined)
    expect(mint).toHaveBeenCalledTimes(2)
  })

  it('scopes recovery and coalescing by connectionId when provided', async () => {
    let release1!: (restored: boolean) => void
    let release2!: (restored: boolean) => void

    const restore = vi.fn(
      (_url: string, connId?: string) =>
        new Promise<boolean>(resolve => {
          if (connId === 'conn-1') {
            release1 = resolve
          } else {
            release2 = resolve
          }
        })
    )

    const run = createCloudSessionRecovery({ hasNativeSession: () => false, restoreCookieSession: restore })
    const mint1 = vi.fn().mockRejectedValueOnce(rejection()).mockResolvedValueOnce('ticket-conn-1')
    const mint2 = vi.fn().mockRejectedValueOnce(rejection()).mockResolvedValueOnce('ticket-conn-2')

    const p1 = run(cloud, mint1, 'conn-1')
    const p2 = run(cloud, mint2, 'conn-2')

    await vi.waitFor(() => expect(restore).toHaveBeenCalledTimes(2))
    expect(restore).toHaveBeenCalledWith(cloud, 'conn-1')
    expect(restore).toHaveBeenCalledWith(cloud, 'conn-2')

    release1(true)
    release2(true)

    expect(await Promise.all([p1, p2])).toEqual(['ticket-conn-1', 'ticket-conn-2'])
  })

  it('does not recover non-Cloud, non-401 or native-session failures', async () => {
    const restore = vi.fn(async () => true)

    const run = createCloudSessionRecovery({
      hasNativeSession: url => url.endsWith('native.agents.nousresearch.com'),
      restoreCookieSession: restore
    })

    for (const [url, status] of [
      ['https://example.com', 401],
      [cloud, 403],
      [cloud, 500],
      ['https://native.agents.nousresearch.com', 401]
    ] as const) {
      const error = rejection(status)
      await expect(
        run(url, async () => {
          throw error
        })
      ).rejects.toBe(error)
    }

    expect(restore).not.toHaveBeenCalled()
  })

  it('coalesces recovery without reusing single-use tickets', async () => {
    let release!: (restored: boolean) => void

    const restore = vi.fn(
      () =>
        new Promise<boolean>(resolve => {
          release = resolve
        })
    )

    const run = createCloudSessionRecovery({ hasNativeSession: () => false, restoreCookieSession: restore })
    const firstMint = vi.fn().mockRejectedValueOnce(rejection()).mockResolvedValueOnce('ticket-1')
    const secondMint = vi.fn().mockRejectedValueOnce(rejection()).mockResolvedValueOnce('ticket-2')
    const first = run(cloud, firstMint)
    const second = run(cloud, secondMint)
    await vi.waitFor(() => expect(restore).toHaveBeenCalledTimes(1))
    release(true)
    expect(await Promise.all([first, second])).toEqual(['ticket-1', 'ticket-2'])
  })

  it('does not retry under a native identity selected during background recovery', async () => {
    let native = false

    const restore = vi.fn(async () => {
      native = true

      return true
    })

    const run = createCloudSessionRecovery({ hasNativeSession: () => native, restoreCookieSession: restore })
    const error = rejection()

    const mint = vi.fn(async () => {
      throw error
    })

    await expect(run(cloud, mint)).rejects.toBe(error)
    expect(mint).toHaveBeenCalledTimes(1)
  })

  it('backs off failed recovery and bounds a successful recovery to one retry', async () => {
    let clock = 0
    const restore = vi.fn().mockResolvedValueOnce(false).mockResolvedValue(true)

    const run = createCloudSessionRecovery({
      hasNativeSession: () => false,
      restoreCookieSession: restore,
      now: () => clock
    })

    const error = rejection()

    const mint = vi.fn(async () => {
      throw error
    })

    await expect(run(cloud, mint)).rejects.toBe(error)
    await expect(run(cloud, mint)).rejects.toBe(error)
    expect(restore).toHaveBeenCalledTimes(1)
    clock = 60_001
    await expect(run(cloud, mint)).rejects.toBe(error)
    expect(restore).toHaveBeenCalledTimes(2)
    expect(mint).toHaveBeenCalledTimes(4)
  })
})
