// Observed: an authoritative wham null limit clears QuotaManager but the same-identity sidebar merge retains the old budget; a populated limit replaces it. The push metadata merge also carries the old budget for both wham and header inputs, though header carry is intentional. A retained reached budget still blocks routing until reset.
import { expect, test } from 'bun:test'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  isOAuthAccount,
  normalizeQuotaHeaders,
  normalizeWham,
  QuotaManager,
  type RefreshAllQuotaDeps,
  refreshAllQuota,
} from '@cortexkit/openai-auth-core/internal'
import { buildSidebarMachineState, mergePushedQuotaMetadata } from '../index.ts'
import {
  getSidebarState,
  type SpendControlReading,
  setSidebarMachineState,
  spendControlExhaustedResetAt,
} from '../sidebar-state.ts'

const RESET = '2026-10-01T00:00:00.000Z'
const NOW = Date.parse('2026-09-25T05:26:00.000Z')
const OLD_BUDGET: SpendControlReading = {
  limit: 2500,
  used: 780.625447511673,
  remaining: 1719.374552488327,
  usedPercent: 31,
  remainingPercent: 69,
  resetsAt: RESET,
  unit: 'credit',
  source: 'workspace_spend_controls',
  reached: false,
}

function wham(individualLimit: boolean) {
  return normalizeWham({
    rate_limit: {
      primary_window: {
        used_percent: 24,
        limit_window_seconds: 604_800,
        reset_at: 1_790_812_800,
      },
      secondary_window: null,
    },
    spend_control: {
      reached: false,
      individual_limit: individualLimit
        ? {
            limit: 2500,
            used: 900,
            remaining: 1600,
            used_percent: 36,
            remaining_percent: 64,
            reset_at: 1_790_812_800,
            unit: 'credit',
            source: 'workspace_spend_controls',
          }
        : null,
    },
  } as Parameters<typeof normalizeWham>[0])
}

async function pollAndRead(
  seed: SpendControlReading,
  individualLimit: boolean,
) {
  const dir = mkdtempSync(join(tmpdir(), 'repro-stale-spend-'))
  const file = join(dir, 'sidebar.json')
  const account = {
    id: 'work-alt',
    type: 'oauth' as const,
    accountId: 'chatgpt-work-alt',
    access: 'work-alt-token',
    refresh: 'work-alt-refresh',
    expires: NOW + 60 * 60_000,
    enabled: true,
  }
  const storage = { version: 1 as const, accounts: [account] }
  const qm = new QuotaManager({
    configPath: join(dir, 'accounts.json'),
    storage,
  })
  const writeSidebarState: RefreshAllQuotaDeps['writeSidebarState'] = async (
    manager,
    store,
  ) => {
    if (store)
      await setSidebarMachineState(
        buildSidebarMachineState(manager, store, NOW),
        file,
      )
  }
  try {
    qm.setFallback(
      account.id,
      {
        quota: {
          primary: {
            usedPercent: 10,
            remainingPercent: 90,
            checkedAt: NOW - 60_000,
          },
          secondary: {
            usedPercent: 30,
            remainingPercent: 70,
            checkedAt: NOW - 60_000,
          },
          spendControl: seed,
        },
        refreshAfter: NOW,
        checkedAt: NOW - 60_000,
      },
      account.access,
      true,
      account.accountId,
    )
    await writeSidebarState(qm, storage)
    const before = await getSidebarState(file)
    expect(before.fallbacks[0]?.quota?.spendControl).toEqual(seed)

    const deps: RefreshAllQuotaDeps = {
      getAuth: async () => ({ type: 'none' }),
      codexRefreshFn: async () => {
        throw new Error('unexpected refresh')
      },
      refreshMainWithLease: async () => {
        throw new Error('unexpected main refresh')
      },
      fallbackManager: {
        refreshAccount: async () => account,
      } as unknown as RefreshAllQuotaDeps['fallbackManager'],
      quotaManager: qm,
      loadAccounts: async () => storage,
      writeSidebarState,
      client: { auth: { set: async () => undefined } },
      fetchImpl: fetch,
      now: () => NOW,
      paths: {
        configPath: join(dir, 'accounts.json'),
        statePath: join(dir, 'state.json'),
      },
      storageMainAccountId: undefined,
      isOAuthAccountFn: isOAuthAccount,
      whamFn: async () => wham(individualLimit),
      readSidebarState: async () => getSidebarState(file),
    }
    const result = await refreshAllQuota(deps, { accountKey: account.id })
    expect(result).toEqual([{ account: 'work-alt', ok: true }])
    return {
      sidebar: (await getSidebarState(file)).fallbacks[0]?.quota,
      cached: qm.peekFallbackForPolicy(account.id, account.accountId)?.quota,
    }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

test('reproduces: a fresh wham null limit leaves the old credit bar in the polled sidebar but clears the quota cache', async () => {
  const { sidebar, cached } = await pollAndRead(OLD_BUDGET, false)
  expect(wham(false).spendControl).toBeUndefined()
  expect(cached?.spendControl).toBeUndefined()
  expect(sidebar?.primary?.usedPercent).toBe(24)
  expect(sidebar?.secondary).toBeUndefined()
  expect(sidebar?.spendControl).toEqual(OLD_BUDGET)
})

test('reproduces: a fresh wham populated limit replaces the old sidebar budget', async () => {
  const { sidebar, cached } = await pollAndRead(OLD_BUDGET, true)
  expect(sidebar?.primary?.usedPercent).toBe(24)
  expect(sidebar?.spendControl?.used).toBe(900)
  expect(cached?.spendControl?.used).toBe(900)
})

test('reproduces: push metadata carries stale budget from a wham null limit; header carry is intended', () => {
  const previous = { spendControl: OLD_BUDGET }
  const nullLimit = wham(false)
  const header = normalizeQuotaHeaders(
    new Headers({
      'x-codex-primary-used-percent': '24',
      'x-codex-primary-window-minutes': '10080',
    }),
  )
  expect(nullLimit.spendControl).toBeUndefined()
  expect(mergePushedQuotaMetadata(nullLimit, previous).spendControl).toEqual(
    OLD_BUDGET,
  )
  expect(mergePushedQuotaMetadata(header, previous).spendControl).toEqual(
    OLD_BUDGET,
  )
})

test('reproduces: a stale reached budget still excludes the account after the no-budget wham poll', async () => {
  const { sidebar, cached } = await pollAndRead(
    { ...OLD_BUDGET, reached: true },
    false,
  )
  expect(spendControlExhaustedResetAt(sidebar, NOW)).toEqual({
    resetsAt: RESET,
    resetAtMs: Date.parse(RESET),
  })
  expect(spendControlExhaustedResetAt(cached, NOW)).toBeUndefined()
})
