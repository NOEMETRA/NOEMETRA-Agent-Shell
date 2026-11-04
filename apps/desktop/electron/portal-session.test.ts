import { EventEmitter } from 'node:events'

import type { BrowserWindow, Session } from 'electron'
import { expect, test, vi } from 'vitest'

import { createPortalSession } from './portal-session'

vi.mock('./window-renderer-lifecycle', () => ({
  installWindowRendererLifecycle: () => {}
}))

class PortalWindow extends EventEmitter {
  readonly webContents = new EventEmitter()
  readonly loadURL: ReturnType<typeof vi.fn>
  private destroyed = false

  constructor(error: Error) {
    super()
    this.loadURL = vi.fn().mockRejectedValue(error)
  }

  isDestroyed() {
    return this.destroyed
  }

  destroy() {
    this.destroyed = true
    this.emit('closed')
  }
}

function portalWithRejectedInitialLoad(error: Error) {
  const win = new PortalWindow(error)
  const cookies: { name: string; value: string }[] = []
  const session = { cookies: { get: async () => cookies } } as unknown as Session

  const portal = createPortalSession({
    isReady: () => true,
    getOauthSession: () => session,
    resolvePortalBaseUrl: () => 'https://portal.example.test',
    warmOauthCookieStore: async () => {},
    createWindow: () => win as unknown as BrowserWindow,
    rememberLog: () => {}
  })

  return { portal, win, cookies }
}

test('a superseded portal navigation stays open until the new access cookie lands', async () => {
  const error = Object.assign(new Error('ERR_ABORTED (-3) loading the portal'), { code: -3 })
  const { portal, win, cookies } = portalWithRejectedInitialLoad(error)

  const result = portal.openPortalLoginWindow().then(
    () => 'landed',
    (failure: Error) => failure.message
  )

  await vi.waitFor(() => expect(win.loadURL).toHaveBeenCalledOnce())
  await new Promise<void>(resolve => setImmediate(resolve))
  expect(win.isDestroyed()).toBe(false)

  cookies.push({ name: 'nas-session', value: 'new-access' })
  win.webContents.emit('did-redirect-navigation')

  expect(await result).toBe('landed')
  expect(win.isDestroyed()).toBe(true)
})

test('a real portal load failure still ends sign-in', async () => {
  const error = Object.assign(new Error('ERR_FAILED (-2) loading the portal'), { code: -2 })
  const { portal, win } = portalWithRejectedInitialLoad(error)

  await expect(portal.openPortalLoginWindow()).rejects.toThrow(error.message)
  expect(win.isDestroyed()).toBe(true)
})

test('partition parameter is forwarded to getOauthSession and warmOauthCookieStore', async () => {
  const requestedPartitions: (string | undefined)[] = []
  const warmedPartitions: (string | undefined)[] = []
  const cookies: { name: string; value: string }[] = [{ name: 'nas-session', value: 'existing-access' }]
  const session = { cookies: { get: async () => cookies } } as unknown as Session

  const portal = createPortalSession({
    isReady: () => true,
    getOauthSession: (part?: string) => {
      requestedPartitions.push(part)
      return session
    },
    resolvePortalBaseUrl: () => 'https://portal.example.test',
    warmOauthCookieStore: async (part?: string) => {
      warmedPartitions.push(part)
    },
    createWindow: () => ({} as unknown as BrowserWindow),
    rememberLog: () => {}
  })

  const live = await portal.hasLivePortalSession('persist:custom-part')
  expect(live).toBe(true)
  expect(requestedPartitions).toContain('persist:custom-part')

  const hasAccess = await portal.hasPortalAccessToken('persist:custom-part')
  expect(hasAccess).toBe(true)
  expect(requestedPartitions).toContain('persist:custom-part')
})

test('concurrent portal renewals are coalesced separately per partition', async () => {
  const windowsCreated: any[] = []
  const session1 = {
    cookies: {
      get: async () => [{ name: 'nas-refresh', value: 'rt1' }]
    }
  } as unknown as Session
  const session2 = {
    cookies: {
      get: async () => [{ name: 'nas-refresh', value: 'rt2' }]
    }
  } as unknown as Session

  const portal = createPortalSession({
    isReady: () => true,
    getOauthSession: (part?: string) => (part === 'persist:part-2' ? session2 : session1),
    resolvePortalBaseUrl: () => 'https://portal.example.test',
    warmOauthCookieStore: async () => {},
    createWindow: options => {
      const win = new PortalWindow(new Error('noop'))
      windowsCreated.push({ options, win })
      return win as unknown as BrowserWindow
    },
    rememberLog: () => {}
  })

  portal.renewPortalAccessSilently({ force: true, partition: 'persist:part-1' }).catch(() => {})
  portal.renewPortalAccessSilently({ force: true, partition: 'persist:part-2' }).catch(() => {})

  await vi.waitFor(() => expect(windowsCreated.length).toBe(2))
  expect(windowsCreated.length).toBe(2)
})
