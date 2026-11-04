/**
 * Authoritative recovery affordance for legacy desktop state preserved alongside newer active intent.
 * (apps/desktop/AGENTS.md:73-78)
 */
import { notify } from '@/store/notifications'

export async function checkLegacyMigrationRecovery(): Promise<void> {
  if (typeof window === 'undefined' || !window.hermesDesktop?.migration?.getRecoveryInfo) {
    return
  }
  try {
    const info = await window.hermesDesktop.migration.getRecoveryInfo()
    if (!info || info.dismissed) return

    if (info.status === 'active-preserved-legacy-available') {
      notify({
        id: 'legacy-migration-recovery-available',
        kind: 'info',
        title: 'Legacy Settings & History Available',
        message: 'Historical settings and sessions from Hermes were preserved alongside your current setup.',
        action: {
          label: 'Restore Legacy Data',
          onClick: async () => {
            const res = await window.hermesDesktop?.migration?.restoreLegacyDatabase?.('all')
            if (!res?.ok) {
              notify({
                id: 'legacy-restore-failed',
                kind: 'error',
                title: 'Restore Failed',
                message: res?.error ? `Could not stage database restore: ${res.error}` : 'Could not stage database restore.'
              })
            }
          }
        },
        secondaryAction: {
          label: 'Keep Current',
          onClick: () => {
            void window.hermesDesktop?.migration?.dismissRecoveryInfo?.()
          }
        },
        durationMs: 0,
        persistent: true
      })
    } else if (info.status === 'intervening-preserved-legacy-active') {
      notify({
        id: 'intervening-migration-recovery-available',
        kind: 'info',
        title: 'Legacy Data Restored',
        message: 'Historical Hermes data is now active. Your previous setup was safely saved and can be restored at any time.',
        action: {
          label: 'Restore Previous Setup',
          onClick: async () => {
            const res = await window.hermesDesktop?.migration?.restoreInterveningDatabase?.('all')
            if (!res?.ok) {
              notify({
                id: 'intervening-restore-failed',
                kind: 'error',
                title: 'Restore Failed',
                message: res?.error ? `Could not stage database restore: ${res.error}` : 'Could not stage database restore.'
              })
            }
          }
        },
        secondaryAction: {
          label: 'Keep Legacy',
          onClick: () => {
            void window.hermesDesktop?.migration?.dismissRecoveryInfo?.()
          }
        },
        durationMs: 0,
        persistent: true
      })
    }
  } catch {
    // Non-blocking recovery check
  }
}

if (typeof window !== 'undefined') {
  setTimeout(() => {
    void checkLegacyMigrationRecovery()
  }, 1000)
}
