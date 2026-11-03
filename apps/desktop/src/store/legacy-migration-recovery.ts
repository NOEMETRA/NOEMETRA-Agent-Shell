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
    if (!info || info.status !== 'active-preserved-legacy-available') {
      return
    }

    notify({
      id: 'legacy-migration-recovery-available',
      kind: 'info',
      title: 'Legacy Settings & History Available',
      message: 'Historical settings and sessions from Hermes were preserved alongside your current setup.',
      action: {
        label: 'Restore Legacy Data',
        onClick: async () => {
          await window.hermesDesktop?.migration?.restoreLegacyDatabase?.('all')
        }
      },
      secondaryAction: {
        label: 'Keep Current',
        onClick: () => {
          void window.hermesDesktop?.migration?.dismissRecoveryInfo?.()
        }
      },
      onDismiss: () => {
        void window.hermesDesktop?.migration?.dismissRecoveryInfo?.()
      },
      durationMs: 0,
      persistent: true
    })
  } catch {
    // Non-blocking recovery check
  }
}

if (typeof window !== 'undefined') {
  setTimeout(() => {
    void checkLegacyMigrationRecovery()
  }, 1000)
}
