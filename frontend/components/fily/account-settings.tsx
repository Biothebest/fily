"use client"

import { RefreshCw, ShieldCheck, Unplug } from "lucide-react"
import type { AccountConnection, AccountConnectionInput, ConnectedAccount, LegacyMigrationStatus, OpaqueId } from "@/lib/fily-api"
import { AccountOnboarding } from "./account-onboarding"
import { LegacyMigrationSettings } from "./legacy-migration-settings"
import { LocalLibrarySettings } from "./local-library-settings"

const STATUS_LABELS: Record<ConnectedAccount["status"], string> = {
  connected: "Connected",
  syncing: "Syncing",
  attention: "Needs attention",
  offline: "Offline",
}

export function AccountSettings({
  accounts,
  syncingId,
  disconnectingId,
  syncNotice,
  onStartSync,
  onRequestDisconnect,
  connection,
  connectionBusy,
  connectionError,
  onBeginConnection,
  onCompleteConnection,
  onResetConnection,
  migrationStatus,
  migrationLoading,
  migrating,
  migrationError,
  onMigrateLegacy,
}: {
  accounts: ConnectedAccount[]
  syncingId: OpaqueId | null
  disconnectingId: OpaqueId | null
  syncNotice: string | null
  onStartSync: (id: OpaqueId) => void
  onRequestDisconnect: (id: OpaqueId) => void
  connection: AccountConnection | null
  connectionBusy: boolean
  connectionError: string | null
  onBeginConnection: (input: AccountConnectionInput) => void
  onCompleteConnection: (connectionId: OpaqueId) => void
  onResetConnection: () => void
  migrationStatus: LegacyMigrationStatus | null
  migrationLoading: boolean
  migrating: boolean
  migrationError: string | null
  onMigrateLegacy: () => void
}) {
  return (
    <section className="h-full flex-1 overflow-y-auto" aria-labelledby="accounts-heading">
      <div className="mx-auto max-w-3xl px-8 py-8">
        <h1 id="accounts-heading" className="text-xl font-semibold">Account settings</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Provider credentials are held by the operating system and trusted Rust core. Fily never exposes them here.
        </p>

        <div className="mt-6 flex items-start gap-3 rounded-lg border border-primary/20 bg-info-muted/40 p-4">
          <ShieldCheck className="mt-0.5 size-5 shrink-0 text-primary" />
          <div>
            <p className="text-sm font-medium">Secure account access</p>
            <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
              Account authorization opens through the provider or native credential flow. This screen never asks for,
              receives, or stores a password, token, key, or filesystem path.
            </p>
          </div>
        </div>
        {syncNotice ? (
          <p className="mt-4 rounded-lg border border-border bg-card p-3 text-sm" role="status">
            {syncNotice}
          </p>
        ) : null}
        <AccountOnboarding
          connection={connection}
          busy={connectionBusy}
          error={connectionError}
          onBegin={onBeginConnection}
          onComplete={onCompleteConnection}
          onReset={onResetConnection}
        />
        <LegacyMigrationSettings
          status={migrationStatus}
          loading={migrationLoading}
          migrating={migrating}
          error={migrationError}
          onMigrate={onMigrateLegacy}
        />
        <LocalLibrarySettings />




        <div className="mt-6 space-y-3">
          {accounts.length === 0 ? (
            <div className="rounded-xl border border-dashed border-border p-8 text-center">
              <p className="text-sm font-medium">No connected accounts</p>
              <p className="mt-1 text-xs text-muted-foreground">
                Add an account from Fily&apos;s secure native connection flow.
              </p>
            </div>
          ) : (
            accounts.map((account) => (
              <article key={account.id} className="rounded-xl border border-border bg-card p-5">
                <div className="flex items-start justify-between gap-5">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="rounded-md bg-secondary px-2 py-1 text-[11px] font-semibold uppercase tracking-wide">
                        {account.provider}
                      </span>
                      <span className="text-xs text-muted-foreground">{STATUS_LABELS[account.status]}</span>
                    </div>
                    <h2 className="mt-3 truncate text-sm font-semibold">{account.displayName || account.email}</h2>
                    <p className="mt-0.5 truncate text-xs text-muted-foreground">{account.email}</p>
                    {account.statusMessage ? (
                      <p className="mt-2 text-xs text-muted-foreground">{account.statusMessage}</p>
                    ) : null}
                    {account.lastSyncedAt ? (
                      <p className="mt-2 flex items-center gap-1 text-[11px] text-muted-foreground">
                        <RefreshCw className="size-3" /> Last synced {account.lastSyncedAt}
                      </p>
                    ) : null}
                  </div>
                  <div className="flex shrink-0 gap-2">
                    <button
                      type="button"
                      disabled={syncingId === account.id || account.status === "syncing"}
                      onClick={() => onStartSync(account.id)}
                      className="flex items-center gap-1.5 rounded-md border border-border px-3 py-2 text-xs font-medium hover:bg-accent disabled:opacity-40"
                    >
                      <RefreshCw className="size-3.5" />
                      {syncingId === account.id ? "Syncing…" : "Sync now"}
                    </button>
                    <button
                      type="button"
                      disabled={disconnectingId === account.id}
                      onClick={() => onRequestDisconnect(account.id)}
                      className="flex items-center gap-1.5 rounded-md border border-destructive/30 px-3 py-2 text-xs font-medium text-destructive hover:bg-destructive/5 disabled:opacity-40"
                    >
                      <Unplug className="size-3.5" />
                      {disconnectingId === account.id ? "Preparing preview…" : "Disconnect…"}
                    </button>
                  </div>
                </div>
              </article>
            ))
          )}
        </div>

        <p className="mt-5 text-xs text-muted-foreground">
          Disconnect is never immediate. Fily creates a reviewable action plan before changing provider access or local data.
        </p>
      </div>
    </section>
  )
}
