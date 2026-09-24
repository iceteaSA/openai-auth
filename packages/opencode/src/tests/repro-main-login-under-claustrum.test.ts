/*
 * Same-account mocked browser login, with the only HTTP boundary stubbed:
 * A. Bound tombstone in Claustrum serves the VAULT-MAIN-TOKEN-tagged JWT.
 * B. Callback succeeds and the simulated host write stores NEW-LOGIN-ACCESS.
 * C. The existing request loader continues serving the vault JWT.
 * D. After a fresh plugin/loader, the new JWT reaches the wire even though
 *    sidebar main custody says INERT:takeover-incomplete (not "never served").
 * E. Local-mode control also serves the new JWT after login.
 * F. An expired new login refreshes locally under Claustrum, then serves the refresh.
 * G. A persisted mismatched fingerprint does not change the sidebar reason;
 *    it remains takeover-incomplete while the new family still reaches the wire.
 * H. Matching crash residue is tombstoned on boot and the vault serves instead.
 */
import { describe, expect, test } from 'bun:test'
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  canonicalCustodyTombstone,
  custodySlotFingerprint,
  loadAccounts,
  saveAccounts,
  writeClaustrumModeAndTransition,
} from '@cortexkit/openai-auth-core/internal'
import { getAccountPaths } from '../core/account-paths.ts'
import { type ClaustrumCacheTransportLike, CodexAuthPlugin } from '../index.ts'
import { getSidebarState } from '../sidebar-state.ts'
import {
  claustrumConfig,
  enrollmentManifest,
  liveStorage,
  makeCustodyRequestJwt,
} from './custody-fixtures.ts'
import { restoreEnv } from './setup-env.ts'

type HostOauth = {
  type: 'oauth'
  access: string
  refresh: string
  expires: number
}
type Deferred = { promise: Promise<void>; resolve(): void }
type Observation = { status: number; authorization: string | undefined }

function deferred(): Deferred {
  let resolve!: () => void
  const promise = new Promise<void>((done) => {
    resolve = done
  })
  return { promise, resolve }
}

async function waitForSleep(sleeps: Deferred[]) {
  for (let turn = 0; turn < 32; turn++) {
    if (sleeps.length) return
    await Promise.resolve()
  }
  throw new Error('expected host readback poller to sleep')
}

async function withLoginHarness(
  mode: 'claustrum' | 'local',
  run: (harness: {
    start(): Promise<void>
    login(): Promise<string>
    request(): Promise<Observation>
    custody(): Promise<unknown>
    expireHostSlot(): void
    stageTransitionMain(access: string, refresh: string): Promise<void>
    putHostSlot(slot: HostOauth): void
    hostSlot(): HostOauth
    transitionMain(): Promise<string | undefined>
    nonResponseRequests: Array<{ url: string; body: string }>
    refreshedAccess: string
    newAccess: string
    vaultAccess: string
  }) => Promise<void>,
) {
  const directory = mkdtempSync(join(tmpdir(), 'repro-main-login-'))
  const configPath = join(directory, 'config.json')
  const manifestPath = join(directory, 'handles.json')
  const originalFetch = globalThis.fetch
  const envKeys = [
    'OPENCODE_OPENAI_AUTH_FILE',
    'OPENCODE_OPENAI_AUTH_STATE_FILE',
    'OPENCODE_OPENAI_AUTH_SIDEBAR_STATE_FILE',
    'OPENCODE_OPENAI_AUTH_LOG_FILE',
    'OPENCODE_CONFIG_DIR',
    'CLAUSTRUM_OPENCODE_HANDLES',
  ] as const
  const previous = Object.fromEntries(
    envKeys.map((key) => [key, process.env[key]]),
  )
  const sleeps: Deferred[] = []
  const newAccess = makeCustodyRequestJwt('acct-main', 'NEW-LOGIN-ACCESS')
  const refreshedAccess = makeCustodyRequestJwt('acct-main', 'REFRESHED-ACCESS')
  const vaultAccess = makeCustodyRequestJwt('acct-main', 'VAULT-MAIN-TOKEN')
  const nonResponseRequests: Array<{ url: string; body: string }> = []
  let hostSlot: HostOauth = canonicalCustodyTombstone('openai')
  let hooks: Awaited<ReturnType<typeof CodexAuthPlugin>> | undefined
  let fetchOverride: typeof globalThis.fetch | undefined
  let authorization: string | undefined
  const transport: ClaustrumCacheTransportLike = {
    getCredential: async () => ({
      material: vaultAccess,
      recordVersion: 71,
      expiresAtMs: Date.now() + 60_000,
    }),
    statusCredential: async () => ({
      ready: true,
      lastErrorCode: null,
      leaseHeld: false,
      recordVersion: 71,
    }),
    reportAuthFailure: async () => {},
    close: () => {},
  }
  try {
    process.env.OPENCODE_OPENAI_AUTH_FILE = configPath
    process.env.OPENCODE_OPENAI_AUTH_STATE_FILE = join(directory, 'state.json')
    process.env.OPENCODE_OPENAI_AUTH_SIDEBAR_STATE_FILE = join(
      directory,
      'sidebar.json',
    )
    process.env.OPENCODE_OPENAI_AUTH_LOG_FILE = join(directory, 'test.log')
    process.env.OPENCODE_CONFIG_DIR = directory
    process.env.CLAUSTRUM_OPENCODE_HANDLES = manifestPath
    await saveAccounts(
      liveStorage([], {
        mainAccountId: 'acct-main',
        claustrum: claustrumConfig({ mode }),
      }),
      getAccountPaths(configPath),
    )
    const manifest = enrollmentManifest('main')
    if (!manifest.ok) throw new Error('expected manifest fixture')
    writeFileSync(manifestPath, JSON.stringify(manifest.value))
    chmodSync(manifestPath, 0o600)
    // Every HTTP call is intercepted; only the explicitly modeled refresh endpoint is allowed.
    globalThis.fetch = (async (url: unknown, init?: RequestInit) => {
      if (String(url).endsWith('/responses')) {
        authorization =
          new Headers(init?.headers).get('authorization') ?? undefined
        return new Response('{}', { status: 200 })
      }
      nonResponseRequests.push({
        url: String(url),
        body: String(init?.body ?? ''),
      })
      if (String(url) !== 'https://auth.openai.com/oauth/token') {
        throw new Error(`unexpected network request: ${String(url)}`)
      }
      return Response.json({
        access_token: refreshedAccess,
        refresh_token: 'REFRESHED-REFRESH',
        expires_in: 3_600,
      })
    }) as typeof globalThis.fetch

    await run({
      newAccess,
      refreshedAccess,
      vaultAccess,
      nonResponseRequests,
      expireHostSlot: () => {
        hostSlot.expires = Date.now() - 60_000
      },
      putHostSlot: (slot) => {
        hostSlot = slot
      },
      hostSlot: () => hostSlot,
      transitionMain: async () =>
        (await loadAccounts(getAccountPaths(configPath)))?.claustrum?.transition
          ?.fingerprints.main,
      stageTransitionMain: async (access, refresh) => {
        await writeClaustrumModeAndTransition(
          getAccountPaths(configPath),
          'claustrum',
          {
            manifestRevision: manifest.revision,
            storeGeneration: 'pretransition-generation',
            fingerprints: {
              main: custodySlotFingerprint(access, refresh),
              fallbacks: {},
            },
          },
        )
      },
      async start() {
        await hooks?.dispose?.()
        hooks = await CodexAuthPlugin(
          {
            client: {
              auth: {
                get: async () => hostSlot,
                all: async () => ({ openai: hostSlot }),
                set: async ({ body }: { body: HostOauth }) => {
                  hostSlot = body
                },
              },
            },
            project: { id: 'test', name: 'test' },
            directory: '',
            worktree: directory,
            experimental_workspace: { register: () => {} },
            serverUrl: new URL('http://localhost:0'),
            $: {},
          } as never,
          {
            custody: {
              transport,
              detection: 'available',
              authorize: {
                browser: async () => ({
                  url: 'http://test.invalid/mock',
                  tokens: Promise.resolve({
                    access_token: newAccess,
                    refresh_token: 'NEW-LOGIN-REFRESH',
                    id_token: newAccess,
                    expires_in: 3_600,
                  }),
                }),
                headless: async () => {
                  throw new Error('headless OAuth must not run')
                },
              },
              sleep: async () => {
                const next = deferred()
                sleeps.push(next)
                await next.promise
              },
            },
          },
        )
        const loaded = await hooks.auth?.loader?.(
          async () => hostSlot,
          {} as never,
        )
        fetchOverride = (loaded as { fetch?: typeof globalThis.fetch })?.fetch
        if (!fetchOverride) throw new Error('expected fetch override')
      },
      async login() {
        const method = hooks?.auth?.methods?.[0]
        if (method?.type !== 'oauth')
          throw new Error('expected main browser method')
        const flow = await method.authorize()
        if (flow.method !== 'auto') throw new Error('expected auto callback')
        const result = await flow.callback()
        await waitForSleep(sleeps)
        // OpenCode, not the callback, persists its result into the host auth slot.
        if (result.type === 'success' && 'refresh' in result) {
          hostSlot = {
            type: 'oauth',
            access: result.access,
            refresh: result.refresh,
            expires: result.expires,
          }
        }
        sleeps.shift()!.resolve()
        for (let turn = 0; turn < 32; turn++) await Promise.resolve()
        return result.type
      },
      async request() {
        if (!fetchOverride) throw new Error('expected fetch override')
        authorization = undefined
        const response = await fetchOverride(
          'https://chatgpt.com/backend-api/codex/responses',
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ model: 'gpt-5.5', input: [] }),
          },
        )
        return { status: response.status, authorization }
      },
      custody: async () => (await getSidebarState()).main.custody,
    })
  } finally {
    for (const sleep of sleeps) sleep.resolve()
    await hooks?.dispose?.()
    globalThis.fetch = originalFetch
    for (const key of envKeys) {
      if (previous[key] === undefined) restoreEnv(key)
      else process.env[key] = previous[key]
    }
    rmSync(directory, { recursive: true, force: true })
  }
}

describe('main browser re-login under Claustrum', () => {
  test('reproduces: restart serves new main login despite inert Claustrum sidebar', async () => {
    await withLoginHarness('claustrum', async (h) => {
      await h.start()
      expect(await h.request()).toEqual({
        status: 200,
        authorization: `Bearer ${h.vaultAccess}`,
      })
      expect(await h.login()).toBe('success')
      const sameProcess = await h.request()
      expect(sameProcess).toEqual({
        status: 200,
        authorization: `Bearer ${h.vaultAccess}`,
      })
      await h.start()
      const restarted = await h.request()
      expect(restarted).toEqual({
        status: 200,
        authorization: `Bearer ${h.newAccess}`,
      })
      expect(await h.custody()).toEqual({
        state: 'inert',
        reason: 'takeover-incomplete',
      })
    })
  })

  test('local-mode control: the same login reaches the wire', async () => {
    await withLoginHarness('local', async (h) => {
      await h.start()
      expect(await h.login()).toBe('success')
      await h.start()
      expect(await h.request()).toEqual({
        status: 200,
        authorization: `Bearer ${h.newAccess}`,
      })
    })
  })

  test('reproduces: expired main re-login refreshes locally while Claustrum is active', async () => {
    await withLoginHarness('claustrum', async (h) => {
      await h.start()
      expect(await h.request()).toEqual({
        status: 200,
        authorization: `Bearer ${h.vaultAccess}`,
      })
      expect(await h.login()).toBe('success')
      h.expireHostSlot()
      await h.start()
      expect(await h.request()).toEqual({
        status: 200,
        authorization: `Bearer ${h.refreshedAccess}`,
      })
      expect(h.nonResponseRequests).toHaveLength(1)
      expect(h.nonResponseRequests[0]?.url).toBe(
        'https://auth.openai.com/oauth/token',
      )
      expect(
        new URLSearchParams(h.nonResponseRequests[0]!.body).get(
          'refresh_token',
        ),
      ).toBe('NEW-LOGIN-REFRESH')
    })
  })

  test('reproduces: mismatched transition fingerprint still reports takeover-incomplete and serves new login', async () => {
    await withLoginHarness('claustrum', async (h) => {
      await h.start()
      expect(await h.request()).toEqual({
        status: 200,
        authorization: `Bearer ${h.vaultAccess}`,
      })
      expect(await h.login()).toBe('success')
      const oldAccess = makeCustodyRequestJwt(
        'acct-main',
        'PRE-TRANSITION-ACCESS',
      )
      await h.stageTransitionMain(oldAccess, 'PRE-TRANSITION-REFRESH')
      await h.start()
      expect(await h.transitionMain()).toBe(
        custodySlotFingerprint(oldAccess, 'PRE-TRANSITION-REFRESH'),
      )
      expect(await h.custody()).toEqual({
        state: 'inert',
        reason: 'takeover-incomplete',
      })
      expect(await h.request()).toEqual({
        status: 200,
        authorization: `Bearer ${h.newAccess}`,
      })
      expect(h.nonResponseRequests).toEqual([])
    })
  })

  test('records crash residue when mode write precedes the main tombstone', async () => {
    await withLoginHarness('claustrum', async (h) => {
      const oldAccess = makeCustodyRequestJwt(
        'acct-main',
        'PRE-TRANSITION-ACCESS',
      )
      h.putHostSlot({
        type: 'oauth',
        access: oldAccess,
        refresh: 'PRE-TRANSITION-REFRESH',
        expires: Date.now() + 60_000,
      })
      await h.stageTransitionMain(oldAccess, 'PRE-TRANSITION-REFRESH')
      await h.start()
      expect(h.hostSlot()).toEqual(canonicalCustodyTombstone('openai'))
      expect(await h.request()).toEqual({
        status: 200,
        authorization: `Bearer ${h.vaultAccess}`,
      })
      expect(await h.custody()).toEqual({ state: 'vault' })
      expect(h.nonResponseRequests).toEqual([])
    })
  })
})
