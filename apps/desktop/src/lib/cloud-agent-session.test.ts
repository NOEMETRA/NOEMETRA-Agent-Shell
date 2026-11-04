import { describe, expect, it, vi } from 'vitest'

import { type CloudAgentSessionBridge, reestablishCloudAgentSession } from './cloud-agent-session'

describe('reestablishCloudAgentSession', () => {
  it('passes connectionId through logout, status, login, and agentSignIn', async () => {
    const logoutMock = vi.fn(async () => {})
    const statusMock = vi.fn(async () => ({ signedIn: false }))
    const loginMock = vi.fn(async () => ({ ok: true, signedIn: true }))
    const agentSignInMock = vi.fn(async () => ({ baseUrl: 'https://test.agents.nousresearch.com', connected: true }))

    const desktop: CloudAgentSessionBridge = {
      oauthLogoutConnectionConfig: logoutMock,
      cloud: {
        status: statusMock,
        login: loginMock,
        agentSignIn: agentSignInMock
      }
    }

    const url = 'https://test.agents.nousresearch.com'
    const connectionId = 'conn-cloud-migrated'

    const outcome = await reestablishCloudAgentSession(desktop, url, connectionId)

    expect(outcome).toBe('connected')
    expect(logoutMock).toHaveBeenCalledWith(url, { connectionId })
    expect(statusMock).toHaveBeenCalledWith({ connectionId })
    expect(loginMock).toHaveBeenCalledWith({ connectionId })
    expect(agentSignInMock).toHaveBeenCalledWith(url, { connectionId })
  })
})
