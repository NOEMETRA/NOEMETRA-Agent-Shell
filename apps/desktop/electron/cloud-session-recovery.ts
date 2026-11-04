import { isNousCloudAgentUrl } from './backend-health'

interface CloudRecoveryDeps {
  hasNativeSession: (baseUrl: string, connectionId?: string) => boolean
  restoreCookieSession: (baseUrl: string, connectionId?: string) => Promise<boolean>
  onRecovered?: (baseUrl: string, connectionId?: string) => void
  now?: () => number
}

/** Coalesce the cookie refresh, never the single-use ticket minted afterward. */
export function createCloudSessionRecovery(deps: CloudRecoveryDeps) {
  const inflight = new Map<string, Promise<boolean>>()
  const failedAt = new Map<string, number>()
  const now = deps.now ?? Date.now

  return async <T>(baseUrl: string, mint: () => Promise<T>, connectionId?: string): Promise<T> => {
    const hadNativeSession = deps.hasNativeSession(baseUrl, connectionId)

    try {
      return await mint()
    } catch (error) {
      if (
        !isNousCloudAgentUrl(baseUrl) ||
        hadNativeSession ||
        deps.hasNativeSession(baseUrl, connectionId) ||
        (error as { statusCode?: number })?.statusCode !== 401
      ) {
        throw error
      }

      const key = connectionId ? `${baseUrl}::${connectionId}` : baseUrl
      let recovery = inflight.get(key)

      if (!recovery) {
        const failed = failedAt.get(key)

        if (failed !== undefined && now() - failed < 60_000) {
          throw error
        }

        recovery = Promise.resolve()
          .then(() => deps.restoreCookieSession(baseUrl, connectionId))
          .catch(() => false)
          .then(restored => {
            if (!restored) {
              failedAt.set(key, now())
            }

            return restored
          })
          .finally(() => inflight.delete(key))
        inflight.set(key, recovery)
      }

      if (!(await recovery)) {
        throw error
      }

      // Native login may have changed while the background cookie flow ran.
      // Never turn that transition into a cross-identity fallback.
      if (deps.hasNativeSession(baseUrl, connectionId)) {
        throw error
      }

      try {
        const ticket = await mint()
        failedAt.delete(key)
        deps.onRecovered?.(baseUrl, connectionId)

        return ticket
      } catch (retryError) {
        failedAt.set(key, now())
        throw retryError
      }
    }
  }
}
