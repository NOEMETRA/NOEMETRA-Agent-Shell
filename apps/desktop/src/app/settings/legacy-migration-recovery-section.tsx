import { type ReactElement, useEffect, useState } from 'react'

import { Button } from '@/components/ui/button'
import { ConfirmDialog } from '@/components/ui/confirm-dialog'
import { Archive } from '@/lib/icons'
import { checkLegacyMigrationRecovery } from '@/store/legacy-migration-recovery'
import { notify } from '@/store/notifications'

import { ListRow } from './primitives'

export function LegacyMigrationRecoverySection(): ReactElement | null {
  const [recoveryInfo, setRecoveryInfo] = useState<any>(null)
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [restoring, setRestoring] = useState(false)

  useEffect(() => {
    let alive = true
    if (typeof window !== 'undefined' && window.hermesDesktop?.migration?.getRecoveryInfo) {
      window.hermesDesktop.migration
        .getRecoveryInfo()
        .then(info => {
          if (alive) {
            setRecoveryInfo(info)
          }
        })
        .catch(() => {})
    }
    return () => {
      alive = false
    }
  }, [])

  if (!recoveryInfo) {
    return null
  }

  const isLegacyAvailable = recoveryInfo.status === 'active-preserved-legacy-available'
  const isInterveningAvailable = recoveryInfo.status === 'intervening-preserved-legacy-active'

  if (!isLegacyAvailable && !isInterveningAvailable && (!recoveryInfo.databases || recoveryInfo.databases.length === 0)) {
    return null
  }

  const handleRestore = async () => {
    setRestoring(true)
    try {
      const res = isInterveningAvailable
        ? await window.hermesDesktop?.migration?.restoreInterveningDatabase?.('all')
        : await window.hermesDesktop?.migration?.restoreLegacyDatabase?.('all')

      if (!res?.ok) {
        setRestoring(false)
        notify({
          id: 'migration-restore-failed',
          kind: 'error',
          title: 'Restore Failed',
          message: res?.error ? `Could not stage restore: ${res.error}` : 'Could not stage restore.'
        })
      }
    } catch (err: any) {
      setRestoring(false)
      notify({
        id: 'migration-restore-error',
        kind: 'error',
        title: 'Restore Error',
        message: err?.message || String(err)
      })
    }
  }

  const title = isInterveningAvailable ? 'Hermes Restored Legacy Data' : 'Preserved Hermes Legacy Data'
  const description = isInterveningAvailable
    ? 'Historical Hermes data is currently active. Your previous setup is safely preserved and can be restored at any time.'
    : 'Historical settings, sessions and databases from Hermes were preserved alongside your current setup.'
  const actionLabel = isInterveningAvailable ? 'Restore Previous Setup' : 'Restore Legacy Data'
  const confirmDesc = isInterveningAvailable
    ? 'The desktop application will safely restore your previous setup snapshot and restart.'
    : 'The desktop application will safely restore historical Hermes databases and restart.'

  return (
    <>
      <ListRow
        action={
          <div className="flex items-center gap-2">
            <Button
              disabled={restoring}
              onClick={() => void checkLegacyMigrationRecovery({ force: true })}
              size="sm"
              variant="text"
            >
              Reopen Banner
            </Button>
            <Button
              disabled={restoring}
              onClick={() => setConfirmOpen(true)}
              size="sm"
              variant="outline"
            >
              <Archive className="size-4" />
              {actionLabel}
            </Button>
          </div>
        }
        description={description}
        id="legacy-migration-recovery-setting"
        title={title}
      />
      <ConfirmDialog
        confirmLabel={actionLabel}
        description={confirmDesc}
        destructive={false}
        onClose={() => setConfirmOpen(false)}
        onConfirm={async () => {
          setConfirmOpen(false)
          await handleRestore()
        }}
        open={confirmOpen}
        title={title}
      />
    </>
  )
}
