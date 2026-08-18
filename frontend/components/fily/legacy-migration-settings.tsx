"use client"

import { Database, LoaderCircle, ShieldCheck } from "lucide-react"
import type { LegacyMigrationStatus } from "@/lib/fily-api"


export interface LegacyMigrationSettingsProps {
  status: LegacyMigrationStatus | null
  loading: boolean
  migrating: boolean
  error: string | null
  onMigrate: () => void
}

export function LegacyMigrationSettings({
  status,
  loading,
  migrating,
  error,
  onMigrate,
}: LegacyMigrationSettingsProps) {
  if (!loading && !error && (!status || status.state === "notFound")) {
    return null
  }

  return (
    <section className="mt-6 rounded-xl border border-border bg-card p-5" aria-labelledby="legacy-migration-heading">
      <div className="flex items-start gap-3">
        <div className="rounded-lg bg-secondary p-2 text-primary" aria-hidden="true">
          {loading || migrating ? <LoaderCircle className="size-4 animate-spin" /> : <Database className="size-4" />}
        </div>
        <div className="min-w-0 flex-1">
          <h2 id="legacy-migration-heading" className="text-sm font-semibold">
            Import an earlier Fily library
          </h2>

          {loading ? (
            <p className="mt-1 text-xs text-muted-foreground" role="status">
              Checking for an earlier local library…
            </p>
          ) : null}

          {!loading && status?.state === "ready" ? (
            <>
              <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
                Fily found Gmail messages from an earlier installation. Import runs in the trusted Rust core, encrypts
                message bodies, and leaves the original library unchanged. Provider credentials are never imported.
              </p>
              <button
                type="button"
                disabled={migrating}
                onClick={onMigrate}
                className="mt-4 inline-flex items-center gap-2 rounded-md bg-primary px-3 py-2 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-40"
              >
                {migrating ? <LoaderCircle className="size-3.5 animate-spin" aria-hidden="true" /> : null}
                {migrating ? "Importing securely…" : "Import messages"}
              </button>
            </>
          ) : null}

          {!loading && status?.state === "completed" ? (
            <div className="mt-2" role="status">
              <p className="flex items-center gap-1.5 text-xs font-medium text-primary">
                <ShieldCheck className="size-3.5" aria-hidden="true" />
                Earlier messages imported securely
              </p>
              <p className="mt-1 text-xs text-muted-foreground">
                {status.accounts.toLocaleString()} {status.accounts === 1 ? "account" : "accounts"} and{" "}
                {status.messages.toLocaleString()} {status.messages === 1 ? "message" : "messages"} imported.
                {status.skipped > 0 ? ` ${status.skipped.toLocaleString()} unsupported records skipped.` : ""}
              </p>
            </div>
          ) : null}

          {error ? (
            <p className="mt-3 rounded-md border border-destructive/30 bg-destructive/5 p-3 text-xs text-destructive" role="alert">
              {error}
            </p>
          ) : null}
        </div>
      </div>
    </section>
  )
}
