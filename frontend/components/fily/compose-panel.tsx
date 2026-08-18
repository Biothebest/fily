"use client"

import { useEffect, useId, useRef, useState } from "react"
import { ArrowLeft, CheckCircle2, Loader2, Send, ShieldCheck, Trash2, X } from "lucide-react"
import { Button } from "@/components/ui/button"
import type { AgentPlan, ConnectedAccount, DraftInput, MailAddress } from "@/lib/fily-api"

export type ComposeMode = "edit" | "preview" | "sent"

export interface ComposeValue extends DraftInput {
  draftId?: string
  inReplyTo?: string | null
}

function addresses(value: string): MailAddress[] {
  return value
    .split(/[;,]/)
    .map((address) => address.trim())
    .filter(Boolean)
    .map((address) => ({ address }))
}

function addressText(values: MailAddress[]): string {
  return values.map((value) => value.address).join(", ")
}

const fieldClass =
  "min-h-9 w-full rounded-md border border-input bg-background px-3 py-2 text-sm outline-none transition-shadow placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/30 disabled:cursor-not-allowed disabled:opacity-60"

export function ComposePanel({
  accounts,
  initialValue,
  preview,
  mode,
  busy,
  error,
  onChange,
  onSaveDraft,
  onDiscard,
  onRequestPreview,
  onBack,
  onConfirmSend,
  onClose,
}: {
  accounts: ConnectedAccount[]
  initialValue: ComposeValue
  preview: AgentPlan | null
  mode: ComposeMode
  busy: "saving" | "previewing" | "sending" | null
  error: string | null
  onChange: (value: ComposeValue) => void
  onSaveDraft: (value: ComposeValue) => void
  onDiscard: () => void
  onRequestPreview: (value: ComposeValue) => void
  onBack: () => void
  onConfirmSend: () => void
  onClose: () => void
}) {
  const [value, setValue] = useState(initialValue)
  const [showCopies, setShowCopies] = useState(initialValue.cc.length > 0 || initialValue.bcc.length > 0)
  const titleId = useId()
  const firstField = useRef<HTMLSelectElement>(null)

  useEffect(() => firstField.current?.focus(), [])
  useEffect(() => setValue(initialValue), [initialValue])

  useEffect(() => {
    function closeOnEscape(event: KeyboardEvent) {
      if (event.key === "Escape" && busy === null) onClose()
    }
    window.addEventListener("keydown", closeOnEscape)
    return () => window.removeEventListener("keydown", closeOnEscape)
  }, [busy, onClose])

  function update(next: Partial<ComposeValue>) {
    const changed = { ...value, ...next }
    setValue(changed)
    onChange(changed)
  }

  const canPreview = Boolean(value.accountId && value.to.length && (value.subject.trim() || value.textBody?.trim()))

  return (
    <div className="fixed inset-0 z-50 flex items-end justify-center bg-foreground/20 p-4 sm:items-center" role="presentation">
      <section
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        className="flex max-h-[calc(100vh-2rem)] w-full max-w-3xl flex-col overflow-hidden rounded-xl border border-border bg-card shadow-xl"
      >
        <header className="flex items-center justify-between border-b border-border px-5 py-4">
          <div>
            <h2 id={titleId} className="font-semibold">
              {mode === "preview" ? "Review before sending" : mode === "sent" ? "Message sent" : value.inReplyTo ? "Reply" : "New message"}
            </h2>
            <p className="mt-0.5 text-xs text-muted-foreground">
              {mode === "preview" ? "Nothing is sent until you confirm below." : "Your sender identity is derived from the connected account."}
            </p>
          </div>
          <Button type="button" variant="ghost" size="icon" onClick={onClose} aria-label="Close compose">
            <X />
          </Button>
        </header>

        {mode === "sent" ? (
          <div className="flex flex-1 flex-col items-center justify-center px-6 py-16 text-center" role="status">
            <CheckCircle2 className="size-9 text-primary" />
            <p className="mt-4 font-semibold">Your message was sent</p>
            <p className="mt-1 max-w-sm text-sm text-muted-foreground">The trusted core recorded the send and saved it to the connected account.</p>
            <Button type="button" className="mt-6" onClick={onClose}>Done</Button>
          </div>
        ) : mode === "preview" && preview ? (
          <div className="overflow-y-auto px-6 py-5">
            <div className="flex items-start gap-3 rounded-lg border border-primary/20 bg-info-muted/50 p-4">
              <ShieldCheck className="mt-0.5 size-5 shrink-0 text-primary" />
              <div>
                <p className="text-sm font-semibold">Explicit confirmation required</p>
                <p className="mt-1 text-xs leading-relaxed text-muted-foreground">This immutable preview can be used once. Review the sender and every recipient before confirming.</p>
              </div>
            </div>
            <dl className="mt-5 grid grid-cols-[5rem_1fr] gap-x-4 gap-y-3 text-sm">
              {preview.preview.map((field) => (
                <div className="col-span-2 grid grid-cols-subgrid" key={field.label}>
                  <dt className="text-muted-foreground">{field.label}</dt>
                  <dd className="whitespace-pre-wrap break-words font-medium">{field.value || "(Empty)"}</dd>
                </div>
              ))}
            </dl>
          </div>
        ) : (
          <form className="min-h-0 flex-1 overflow-y-auto px-5 py-4" onSubmit={(event) => { event.preventDefault(); if (canPreview) onRequestPreview(value) }}>
            <div className="grid gap-4">
              <label className="grid gap-1.5 text-xs font-medium" htmlFor={`${titleId}-from`}>
                From connected account
                <select ref={firstField} id={`${titleId}-from`} className={fieldClass} value={value.accountId} onChange={(event) => update({ accountId: event.target.value })} disabled={busy !== null} required>
                  <option value="">Choose an account</option>
                  {accounts.filter((account) => account.status === "connected").map((account) => <option key={account.id} value={account.id}>{account.displayName ? `${account.displayName} · ` : ""}{account.email}</option>)}
                </select>
              </label>
              <label className="grid gap-1.5 text-xs font-medium" htmlFor={`${titleId}-to`}>
                To
                <input id={`${titleId}-to`} className={fieldClass} type="text" inputMode="email" autoComplete="off" value={addressText(value.to)} onChange={(event) => update({ to: addresses(event.target.value) })} placeholder="name@example.com" disabled={busy !== null} required />
              </label>
              {!showCopies ? <Button type="button" variant="link" className="h-auto w-fit p-0 text-xs" onClick={() => setShowCopies(true)}>Add Cc or Bcc</Button> : (
                <div className="grid gap-4 sm:grid-cols-2">
                  <label className="grid gap-1.5 text-xs font-medium" htmlFor={`${titleId}-cc`}>Cc<input id={`${titleId}-cc`} className={fieldClass} value={addressText(value.cc)} onChange={(event) => update({ cc: addresses(event.target.value) })} disabled={busy !== null} /></label>
                  <label className="grid gap-1.5 text-xs font-medium" htmlFor={`${titleId}-bcc`}>Bcc<input id={`${titleId}-bcc`} className={fieldClass} value={addressText(value.bcc)} onChange={(event) => update({ bcc: addresses(event.target.value) })} disabled={busy !== null} /></label>
                </div>
              )}
              <label className="grid gap-1.5 text-xs font-medium" htmlFor={`${titleId}-subject`}>Subject<input id={`${titleId}-subject`} className={fieldClass} value={value.subject} onChange={(event) => update({ subject: event.target.value })} disabled={busy !== null} /></label>
              <label className="grid gap-1.5 text-xs font-medium" htmlFor={`${titleId}-body`}>Message<textarea id={`${titleId}-body`} className={`${fieldClass} min-h-56 resize-y leading-6`} value={value.textBody ?? ""} onChange={(event) => update({ textBody: event.target.value })} disabled={busy !== null} required /></label>
            </div>
            <button type="submit" className="sr-only">Review message</button>
          </form>
        )}

        {error ? <div className="border-t border-destructive/20 bg-destructive/10 px-5 py-3 text-sm text-destructive" role="alert">{error}</div> : null}
        {mode !== "sent" ? (
          <footer className="flex flex-wrap items-center justify-between gap-3 border-t border-border px-5 py-4">
            {mode === "preview" ? <Button type="button" variant="outline" onClick={onBack} disabled={busy !== null}><ArrowLeft /> Edit message</Button> : <Button type="button" variant="destructive" onClick={onDiscard} disabled={busy !== null}><Trash2 /> Discard</Button>}
            <div className="flex items-center gap-2">
              {mode === "edit" ? <Button type="button" variant="secondary" onClick={() => onSaveDraft(value)} disabled={busy !== null}>{busy === "saving" ? <Loader2 className="animate-spin" /> : null}Save draft</Button> : null}
              {mode === "edit" ? <Button type="button" onClick={() => onRequestPreview(value)} disabled={busy !== null || !canPreview}>Review send</Button> : null}
              {mode === "preview" ? <Button type="button" onClick={onConfirmSend} disabled={busy !== null}>{busy === "sending" ? <Loader2 className="animate-spin" /> : <Send />}Confirm and send</Button> : null}
            </div>
          </footer>
        ) : null}
      </section>
    </div>
  )
}
