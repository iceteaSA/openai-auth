import { describe, expect, test } from 'bun:test'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  type AccountPaths,
  type AccountStorage,
  loadAccounts,
  type OAuthAccount,
  saveAccountState,
  saveAccounts,
} from '../internal.ts'

function storage(account: OAuthAccount): AccountStorage {
  return {
    version: 1,
    main: { type: 'opencode', provider: 'openai' },
    claustrum: { mode: 'local' },
    accounts: [account],
  }
}

describe('future refresh stamp reproduction', () => {
  test.each([
    ['future stored stamp', 6 * 60 * 60_000, 'OLD'],
    ['past stored stamp (control)', -60 * 60_000, 'NEW'],
  ] as const)('%s', async (_label, storedOffset, surviving) => {
    const directory = mkdtempSync(join(tmpdir(), 'future-refresh-'))
    const paths: AccountPaths = {
      configPath: join(directory, 'config.json'),
      statePath: join(directory, 'state.json'),
    }
    const now = Date.now()
    try {
      const original: OAuthAccount = {
        id: 'fallback',
        type: 'oauth',
        access: 'OLD',
        refresh: 'OLD-REFRESH',
        lastRefreshedAt: now + storedOffset,
        expires: now - 60_000,
      }
      await saveAccounts(storage(original), paths)
      await saveAccountState(
        storage({
          ...original,
          access: 'NEW',
          refresh: 'NEW-REFRESH',
          lastRefreshedAt: now,
          expires: now + 60 * 60_000,
        }),
        paths,
      )

      const saved = (await loadAccounts(paths))?.accounts[0] as OAuthAccount
      expect(saved.access).toBe(surviving)
      expect(saved.refresh).toBe(`${surviving}-REFRESH`)
      expect(saved.expires).toBe(
        surviving === 'OLD' ? now - 60_000 : now + 60 * 60_000,
      )
      expect(saved.lastRefreshedAt).toBe(
        surviving === 'OLD' ? now + storedOffset : now,
      )
      if (surviving === 'OLD') expect(saved.expires).toBeLessThan(now)
    } finally {
      rmSync(directory, { recursive: true, force: true })
    }
  })
})
