"use client"

import { useState } from "react"
import { Check, ExternalLink, KeyRound, Loader2, MailPlus } from "lucide-react"
import type { AccountConnection, AccountConnectionInput, ProviderKind } from "@/lib/fily-api"

const PROVIDERS: Array<{
  kind: ProviderKind
  name: string
  description: string
  authorization: string
}> = [
  {
    kind: "gmail",
    name: "Gmail",
    description: "Google authorization with PKCE",
    authorization: "Your browser opens for Google sign-in.",
  },
  {
    kind: "imap",
    name: "IMAP",
    description: "Any standards-based mail provider",
    authorization: "A native secure credential window opens.",
  },
  {
    kind: "yahoo",
    name: "Yahoo Mail",
    description: "Yahoo app-password connection",
    authorization: "A native secure credential window opens.",
  },
  {
    kind: "icloud",
    name: "iCloud Mail",
    description: "Apple app-specific password connection",
    authorization: "A native secure credential window opens.",
  },
]

const PHASE_LABELS: Record<AccountConnection["phase"], string> = {
  awaiting_authorization: "Waiting for provider authorization",
  capturing_credentials: "Waiting for native secure input",
  connecting: "Verifying the account",
  connected: "Account connected",
  cancelled: "Connection cancelled",
  failed: "Connection could not be completed",
}

export function AccountOnboarding({
  connection,
  busy,
  error,
  onBegin,
  onComplete,
  onReset,
}: {
  connection: AccountConnection | null
  busy: boolean
  error: string | null
  onBegin: (input: AccountConnectionInput) => void
  onComplete: (connectionId: string) => void
  onReset: () => void
}) {
  const [selected, setSelected] = useState<ProviderKind | null>(null)
  const [email, setEmail] = useState("")
  const [username, setUsername] = useState("")
  const [imapHost, setImapHost] = useState("")
  const [imapPort, setImapPort] = useState("993")
  const [smtpPort, setSmtpPort] = useState("587")
  const [smtpHost, setSmtpHost] = useState("")

  function submitPublicConfiguration() {
    if (!selected) return
    const normalizedEmail = email.trim().toLowerCase()
    if (selected === "imap") {
      onBegin({
        provider: selected,
        email: normalizedEmail,
        imapConfiguration: {
          imapHost: imapHost.trim().toLowerCase(),
          imapPort: Number(imapPort),
          smtpHost: smtpHost.trim().toLowerCase(),
          smtpPort: Number(smtpPort),
          username: username.trim() || normalizedEmail,
        },
      })
      return
    }
    onBegin({ provider: selected, email: normalizedEmail })
  }
  if (connection) {
    const waiting = connection.phase !== "connected" && connection.phase !== "cancelled" && connection.phase !== "failed"
    return (
      <section className="mt-6 rounded-xl border border-primary/20 bg-card p-5" aria-labelledby="connection-heading">
        <div className="flex items-start gap-3">
          {connection.phase === "connected" ? (
            <Check className="mt-0.5 size-5 text-success" />
          ) : waiting || busy ? (
            <Loader2 className="mt-0.5 size-5 animate-spin text-primary" />
          ) : (
            <KeyRound className="mt-0.5 size-5 text-muted-foreground" />
          )}
          <div className="min-w-0 flex-1">
            <p id="connection-heading" className="text-sm font-semibold">
              {PHASE_LABELS[connection.phase]}
            </p>
            <p className="mt-1 text-xs text-muted-foreground">
              {connection.statusMessage || "The trusted Rust core owns authorization and credential storage."}
            </p>
            {connection.phase === "awaiting_authorization" ? (
              <p className="mt-2 flex items-center gap-1 text-xs text-muted-foreground">
                <ExternalLink className="size-3" /> Continue in the system browser, then return to Fily.
              </p>
            ) : null}
            {error ? <p className="mt-3 text-xs text-destructive" role="alert">{error}</p> : null}
            <div className="mt-4 flex gap-2">
              {waiting ? (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => onComplete(connection.connectionId)}
                  className="rounded-md bg-primary px-3 py-2 text-xs font-semibold text-primary-foreground disabled:opacity-40"
                >
                  {busy ? "Checking…" : "Finish secure connection"}
                </button>
              ) : null}
              <button
                type="button"
                disabled={busy}
                onClick={onReset}
                className="rounded-md border border-border px-3 py-2 text-xs font-medium hover:bg-accent disabled:opacity-40"
              >
                {connection.phase === "connected" ? "Add another account" : "Choose another provider"}
              </button>
            </div>
          </div>
        </div>
      </section>
    )
  }

  return (
    <section className="mt-6" aria-labelledby="add-account-heading">
      <div className="flex items-center gap-2">
        <MailPlus className="size-4 text-primary" />
        <h2 id="add-account-heading" className="text-sm font-semibold">Add an account</h2>
      </div>
      <p className="mt-1 text-xs text-muted-foreground">
        Choose a provider. Passwords and tokens are captured and stored natively and never enter this screen.
      </p>
      {error ? <p className="mt-3 text-xs text-destructive" role="alert">{error}</p> : null}
      <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
        {PROVIDERS.map((provider) => (
          <button
            key={provider.kind}
            type="button"
            disabled={busy}
            onClick={() => {
              setSelected(provider.kind)
              if (provider.kind === "gmail") onBegin({ provider: "gmail" })
            }}
            className="rounded-xl border border-border bg-card p-4 text-left transition-colors hover:border-primary/40 hover:bg-accent disabled:opacity-40"
          >
            <span className="text-sm font-semibold">{provider.name}</span>
            <span className="mt-1 block text-xs text-muted-foreground">{provider.description}</span>
            <span className="mt-3 block text-[11px] text-muted-foreground">{provider.authorization}</span>
          </button>
        ))}
      </div>
      {selected === "gmail" ? (
        <div className="mt-4 rounded-xl border border-primary/20 bg-card p-4" role="status">
          <p className="flex items-center gap-2 text-sm font-semibold">
            {busy ? <Loader2 className="size-4 animate-spin text-primary" /> : <ExternalLink className="size-4 text-primary" />}
            {busy ? "Waiting for Google authorization" : "Google authorization"}
          </p>
          <p className="mt-2 text-xs text-muted-foreground">
            Fily opens the system browser and completes the PKCE callback in Rust. No token enters this screen.
          </p>
          {!busy ? (
            <button
              type="button"
              onClick={() => onBegin({ provider: "gmail" })}
              className="mt-3 rounded-md border border-border px-3 py-2 text-xs font-medium hover:bg-accent"
            >
              Open Google authorization
            </button>
          ) : null}
        </div>
      ) : selected ? (
        <form
          className="mt-4 rounded-xl border border-border bg-card p-4"
          onSubmit={(event) => {
            event.preventDefault()
            submitPublicConfiguration()
          }}
        >
          <p className="text-sm font-semibold">
            {PROVIDERS.find((provider) => provider.kind === selected)?.name} public account details
          </p>
          <p className="mt-1 text-xs text-muted-foreground">
            The password is requested next in an operating-system secure field, never in React.
          </p>
          <label className="mt-4 block text-xs font-medium">
            Email address
            <input
              required
              type="email"
              autoComplete="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              className="mt-1 block w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
            />
          </label>
          {selected === "imap" ? (
            <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2">
              <label className="text-xs font-medium">
                IMAP host
                <input
                  required
                  value={imapHost}
                  onChange={(event) => setImapHost(event.target.value)}
                  placeholder="imap.example.com"
                  className="mt-1 block w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
                />
              </label>
              <label className="text-xs font-medium">
                IMAP port
                <input
                  required
                  type="number"
                  min={1}
                  max={65535}
                  value={imapPort}
                  onChange={(event) => setImapPort(event.target.value)}
                  className="mt-1 block w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
                />
              </label>
              <label className="text-xs font-medium">
                SMTP host
                <input
                  required
                  value={smtpHost}
                  onChange={(event) => setSmtpHost(event.target.value)}
                  placeholder="smtp.example.com"
                  className="mt-1 block w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
                />
              </label>
              <label className="text-xs font-medium">
                SMTP port
                <input
                  required
                  type="number"
                  min={1}
                  max={65535}
                  value={smtpPort}
                  onChange={(event) => setSmtpPort(event.target.value)}
                  className="mt-1 block w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
                />
              </label>
              <label className="text-xs font-medium sm:col-span-2">
                Username
                <input
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  placeholder="Defaults to the email address"
                  className="mt-1 block w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
                />
              </label>
            </div>
          ) : null}
          <div className="mt-4 flex gap-2">
            <button
              type="submit"
              disabled={busy}
              className="rounded-md bg-primary px-3 py-2 text-xs font-semibold text-primary-foreground disabled:opacity-40"
            >
              {busy ? "Opening secure input…" : "Continue securely"}
            </button>
            <button
              type="button"
              disabled={busy}
              onClick={() => setSelected(null)}
              className="rounded-md border border-border px-3 py-2 text-xs font-medium hover:bg-accent disabled:opacity-40"
            >
              Cancel
            </button>
          </div>
        </form>
      ) : null}
    </section>
  )
}
