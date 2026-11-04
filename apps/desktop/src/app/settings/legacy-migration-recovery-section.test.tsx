// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import * as legacyRecovery from '@/store/legacy-migration-recovery'

import { LegacyMigrationRecoverySection } from './legacy-migration-recovery-section'

describe('LegacyMigrationRecoverySection', () => {
  const getRecoveryInfo = vi.fn()
  const restoreLegacyDatabase = vi.fn()
  const restoreInterveningDatabase = vi.fn()
  const dismissRecoveryInfo = vi.fn()
  const checkLegacyMigrationRecoverySpy = vi.spyOn(legacyRecovery, 'checkLegacyMigrationRecovery')

  beforeEach(() => {
    vi.clearAllMocks()
    window.hermesDesktop = {
      ...((window.hermesDesktop as any) || {}),
      migration: {
        getRecoveryInfo,
        restoreLegacyDatabase,
        restoreInterveningDatabase,
        dismissRecoveryInfo
      }
    } as any
  })

  afterEach(() => {
    cleanup()
  })

  it('renders nothing when no recovery info is found', async () => {
    getRecoveryInfo.mockResolvedValue(null)
    const { container } = render(<LegacyMigrationRecoverySection />)
    await waitFor(() => expect(getRecoveryInfo).toHaveBeenCalled())
    expect(container.firstChild).toBeNull()
  })

  it('renders persistent affordance when legacy data was preserved even if dismissed', async () => {
    getRecoveryInfo.mockResolvedValue({
      status: 'active-preserved-legacy-available',
      dismissed: true,
      databases: [{ name: 'state.db', legacyPreserved: 'state.db.legacy', activeRetained: 'state.db' }]
    })

    render(<LegacyMigrationRecoverySection />)
    await screen.findByText('Preserved Hermes Legacy Data')
    expect(screen.getByText('Reopen Banner')).toBeTruthy()
    expect(screen.getByText('Restore Legacy Data')).toBeTruthy()

    // Clicking Reopen Banner calls checkLegacyMigrationRecovery with force: true
    fireEvent.click(screen.getByText('Reopen Banner'))
    expect(checkLegacyMigrationRecoverySpy).toHaveBeenCalledWith({ force: true })

    // Clicking Restore Legacy Data opens confirm dialog
    restoreLegacyDatabase.mockResolvedValue({ ok: true, relaunching: true })
    fireEvent.click(screen.getByText('Restore Legacy Data'))

    // The confirm dialog has action button
    const confirmButtons = screen.getAllByRole('button', { name: 'Restore Legacy Data' })
    const confirmBtn = confirmButtons[confirmButtons.length - 1]
    fireEvent.click(confirmBtn)

    await waitFor(() => expect(restoreLegacyDatabase).toHaveBeenCalledWith('all'))
  })

  it('handles intervening preserved recovery state and calls restoreInterveningDatabase', async () => {
    getRecoveryInfo.mockResolvedValue({
      status: 'intervening-preserved-legacy-active',
      dismissed: true,
      databases: [{ name: 'state.db', interveningPreserved: 'state.db.intervening' }]
    })

    render(<LegacyMigrationRecoverySection />)
    await screen.findByText('Hermes Restored Legacy Data')
    expect(screen.getByText('Restore Previous Setup')).toBeTruthy()

    restoreInterveningDatabase.mockResolvedValue({ ok: true, relaunching: true })
    fireEvent.click(screen.getByText('Restore Previous Setup'))

    const confirmButtons = screen.getAllByRole('button', { name: 'Restore Previous Setup' })
    const confirmBtn = confirmButtons[confirmButtons.length - 1]
    fireEvent.click(confirmBtn)

    await waitFor(() => expect(restoreInterveningDatabase).toHaveBeenCalledWith('all'))
  })
})
