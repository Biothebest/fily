"use client"

import { FileText, ShieldCheck } from "lucide-react"
import type { SanitizedMessage } from "@/lib/fily-api"

function addressList(message: SanitizedMessage): string {
  return message.recipients
    .map((recipient) => recipient.name?.trim() || recipient.address)
    .join(", ")
}

export function MessageViewer({
  message,
  loading,
  error,
}: {
  message: SanitizedMessage | null
  loading: boolean
  error: string | null
}) {
  if (loading) {
    return <div className="flex flex-1 items-center justify-center text-sm text-muted-foreground">Opening message…</div>
  }

  if (error) {
    return (
      <div className="flex flex-1 items-center justify-center p-8 text-center">
        <div>
          <p className="font-medium">Message unavailable</p>
          <p className="mt-1 text-sm text-muted-foreground">{error}</p>
        </div>
      </div>
    )
  }

  if (!message) {
    return (
      <div className="flex flex-1 items-center justify-center p-8 text-center text-sm text-muted-foreground">
        Select a message to read its safe local copy.
      </div>
    )
  }

  const sender = message.sender.name?.trim() || message.sender.address
  const recipients = addressList(message)

  return (
    <article className="min-w-0 flex-1 overflow-y-auto bg-card" aria-labelledby="message-subject">
      <header className="border-b border-border px-7 py-5">
        <div className="flex items-start justify-between gap-6">
          <div className="min-w-0">
            <h2 id="message-subject" className="text-xl font-semibold leading-tight">
              {message.subject || "(No subject)"}
            </h2>
            <p className="mt-3 text-sm">
              <span className="font-medium">{sender}</span>{" "}
              <span className="text-muted-foreground">&lt;{message.sender.address}&gt;</span>
            </p>
            <p className="mt-0.5 text-xs text-muted-foreground">To: {recipients || "Undisclosed recipients"}</p>
          </div>
          <time className="shrink-0 text-xs text-muted-foreground">{message.receivedAt}</time>
        </div>
      </header>

      <div className="px-7 py-6">
        {message.remoteContentBlocked ? (
          <div className="mb-5 flex items-start gap-2 rounded-lg border border-primary/20 bg-info-muted/50 px-3 py-2.5 text-xs">
            <ShieldCheck className="mt-0.5 size-4 shrink-0 text-primary" />
            <div>
              <p className="font-medium">Remote content blocked</p>
              <p className="mt-0.5 text-muted-foreground">
                Fily displays sanitized text only. Tracking pixels, remote images, scripts, and links were not loaded.
              </p>
            </div>
          </div>
        ) : null}

        <div className="whitespace-pre-wrap break-words text-[14px] leading-7 text-foreground/90">
          {message.bodyText || "This message has no displayable text content."}
        </div>

        {message.attachments.length > 0 ? (
          <section className="mt-8 border-t border-border pt-5" aria-labelledby="attachment-heading">
            <h3 id="attachment-heading" className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Attachments
            </h3>
            <ul className="mt-3 grid gap-2 sm:grid-cols-2">
              {message.attachments.map((attachment) => (
                <li key={attachment.id} className="flex items-center gap-3 rounded-lg border border-border p-3">
                  <FileText className="size-4 shrink-0 text-muted-foreground" />
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium">{attachment.filename}</p>
                    <p className="text-xs text-muted-foreground">
                      {attachment.mediaType} · {Math.ceil(attachment.sizeBytes / 1024).toLocaleString()} KB
                    </p>
                  </div>
                </li>
              ))}
            </ul>
            <p className="mt-2 text-xs text-muted-foreground">
              Attachment contents remain in the trusted core until you explicitly request an action.
            </p>
          </section>
        ) : null}
      </div>
    </article>
  )
}
