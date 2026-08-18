"use client"

import { useState } from "react"
import {
  Mail,
  Quote,
  ArrowRight,
  PanelRightClose,
  PanelRightOpen,
  Sparkles,
  CornerDownLeft,
} from "lucide-react"
import { cn } from "@/lib/utils"
import type { FilyApi, JobApplication } from "@/lib/fily-api"
import { StatusBadge } from "./status-badge"

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">{label}</dt>
      <dd className="mt-1 text-sm text-foreground">{children}</dd>
    </div>
  )
}

function AskFily({ application, api }: { application: JobApplication; api: FilyApi }) {
  const [question, setQuestion] = useState("")
  const [answer, setAnswer] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  async function submit() {
    const q = question.trim()
    if (!q || pending) return
    setPending(true)
    try {
      const result = await api.askFily(`${q}\nApplication: ${application.company} — ${application.position}`)
      setAnswer(result.answer)
      setQuestion("")
    } catch (error) {
      setAnswer(error instanceof Error ? error.message : "Fily could not answer that question.")
    } finally {
      setPending(false)
    }
  }

  return (
    <div className="border-t border-border bg-secondary/40 p-4">
      <div className="mb-2 flex items-center gap-1.5 text-xs font-medium text-foreground">
        <Sparkles className="size-3.5 text-primary" />
        Ask Fily about {application.company}
      </div>

      {answer && (
        <p className="mb-2 rounded-md border border-border bg-card p-2.5 text-xs leading-relaxed text-muted-foreground">
          {answer}
        </p>
      )}

      <form
        className="flex items-center gap-2 rounded-lg border border-border bg-card px-2.5 py-1.5 focus-within:border-primary/50 focus-within:ring-2 focus-within:ring-ring/15"
        onSubmit={(e) => {
          e.preventDefault()
          submit()
        }}
      >
        <input
          type="text"
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          className="min-w-0 flex-1 bg-transparent text-sm text-foreground placeholder:text-muted-foreground focus:outline-none"
          aria-label={`Ask Fily about ${application.company}`}
        />
        <button
          type="submit"
          disabled={!question.trim() || pending}
          className="flex size-7 shrink-0 items-center justify-center rounded-md bg-primary text-primary-foreground transition-opacity disabled:opacity-40"
          aria-label="Send question to Fily"
        >
          <CornerDownLeft className="size-3.5" />
        </button>
      </form>
    </div>
  )
}

export function ApplicationDetail({
  application,
  collapsed,
  onToggle,
  api,
}: {
  application: JobApplication | null
  collapsed: boolean
  onToggle: () => void
  api: FilyApi
}) {
  if (collapsed) {
    return (
      <div className="flex h-full w-12 shrink-0 flex-col items-center border-l border-border bg-card py-3">
        <button
          type="button"
          onClick={onToggle}
          className="flex size-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
          aria-label="Expand assistant panel"
        >
          <PanelRightOpen className="size-4" />
        </button>
      </div>
    )
  }

  return (
    <aside className="flex h-full w-96 shrink-0 flex-col border-l border-border bg-card">
      <header className="flex h-12 items-center justify-between border-b border-border px-4">
        <span className="text-sm font-semibold text-foreground">Application details</span>
        <button
          type="button"
          onClick={onToggle}
          className="flex size-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
          aria-label="Collapse assistant panel"
        >
          <PanelRightClose className="size-4" />
        </button>
      </header>

      {!application ? (
        <div className="flex flex-1 items-center justify-center px-6 text-center text-sm text-muted-foreground">
          Select an application to see its details.
        </div>
      ) : (
        <div className="flex min-h-0 flex-1 flex-col">
          <div className="min-h-0 flex-1 overflow-y-auto">
            <div className="border-b border-border p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <h2 className="truncate text-base font-semibold text-foreground">{application.company}</h2>
                  <p className="mt-0.5 text-sm text-muted-foreground">{application.position}</p>
                </div>
                <StatusBadge stage={application.stage} className="mt-0.5 shrink-0" />
              </div>
            </div>

            <dl className="grid grid-cols-2 gap-4 border-b border-border p-4">
              <Field label="Company">{application.company}</Field>
              <Field label="Role">{application.position}</Field>
              <Field label="Current stage">
                <StatusBadge stage={application.stage} />
              </Field>
              <Field label="Application date">
                <span className="tabular-nums">{application.applicationDate}</span>
              </Field>
            </dl>

            <div className="border-b border-border p-4">
              <div className="mb-2 flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
                <Quote className="size-3.5" />
                Evidence from confirmation email
              </div>
              <div className="rounded-lg border border-border bg-secondary/40 p-3">
                <p className="text-[13px] font-medium text-foreground">{application.evidence.subject}</p>
                <p className="mt-0.5 text-xs text-muted-foreground">
                  {application.evidence.from} · {application.evidence.receivedAt}
                </p>
                <p className="mt-2 border-l-2 border-primary/40 pl-2.5 text-[13px] leading-relaxed text-muted-foreground">
                  {application.evidence.quote}
                </p>
              </div>
            </div>

            <div className="border-b border-border p-4">
              <div className="mb-2 flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
                <Mail className="size-3.5" />
                Related email thread
              </div>
              <ul className="space-y-1">
                {application.thread.map((msg) => (
                  <li
                    key={msg.id}
                    className="flex items-start gap-2.5 rounded-md p-2 transition-colors hover:bg-accent/50"
                  >
                    <span
                      className={cn(
                        "mt-1.5 size-1.5 shrink-0 rounded-full",
                        msg.unread ? "bg-primary" : "bg-transparent",
                      )}
                      aria-hidden="true"
                    />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center justify-between gap-2">
                        <span
                          className={cn(
                            "truncate text-[13px]",
                            msg.unread ? "font-semibold text-foreground" : "font-medium text-foreground/90",
                          )}
                        >
                          {msg.fromName}
                        </span>
                        <span className="shrink-0 text-xs text-muted-foreground">
                          {msg.date} · {msg.time}
                        </span>
                      </div>
                      <p className="mt-0.5 truncate text-xs text-muted-foreground">{msg.preview}</p>
                    </div>
                  </li>
                ))}
              </ul>
            </div>

            <div className="p-4">
              <div className="mb-2 flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
                <ArrowRight className="size-3.5" />
                Next action
              </div>
              <div className="flex items-start gap-2 rounded-lg border border-primary/20 bg-info-muted/50 p-3">
                <p className="text-[13px] leading-relaxed text-foreground">{application.nextAction}</p>
              </div>
            </div>
          </div>

          <AskFily application={application} api={api} />
        </div>
      )}
    </aside>
  )
}
