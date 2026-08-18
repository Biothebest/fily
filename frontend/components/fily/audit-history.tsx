"use client"

import { Bot, CheckCircle2, ShieldX, UserRound, XCircle } from "lucide-react"
import type { AuditEvent } from "@/lib/fily-api"

const ACTOR_ICONS = {
  user: UserRound,
  agent: Bot,
  system: CheckCircle2,
}

const OUTCOME_ICONS = {
  allowed: CheckCircle2,
  denied: ShieldX,
  failed: XCircle,
}

export function AuditHistory({
  events,
  loading,
  error,
  canLoadMore,
  onLoadMore,
}: {
  events: AuditEvent[]
  loading: boolean
  error: string | null
  canLoadMore: boolean
  onLoadMore: () => void
}) {
  return (
    <section className="h-full flex-1 overflow-y-auto" aria-labelledby="audit-heading">
      <div className="mx-auto max-w-4xl px-8 py-8">
        <h1 id="audit-heading" className="text-xl font-semibold">Audit history</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          A local, append-only view of authorization decisions and completed actions.
        </p>

        {error ? <p className="mt-4 rounded-lg border border-destructive/30 p-3 text-sm text-destructive">{error}</p> : null}

        {events.length === 0 && !loading ? (
          <p className="py-16 text-center text-sm text-muted-foreground">No audited actions yet.</p>
        ) : (
          <ol className="mt-6 space-y-2">
            {events.map((event) => {
              const ActorIcon = ACTOR_ICONS[event.actor]
              const OutcomeIcon = OUTCOME_ICONS[event.outcome]
              return (
                <li key={event.id} className="rounded-xl border border-border bg-card p-4">
                  <div className="flex items-start gap-3">
                    <span className="flex size-8 shrink-0 items-center justify-center rounded-full bg-secondary">
                      <ActorIcon className="size-4 text-muted-foreground" />
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-start justify-between gap-4">
                        <div>
                          <p className="text-sm font-medium">{event.action}</p>
                          <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{event.summary}</p>
                        </div>
                        <span className="flex shrink-0 items-center gap-1 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
                          <OutcomeIcon className="size-3.5" /> {event.outcome}
                        </span>
                      </div>
                      <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
                        <time>{event.occurredAt}</time>
                        <span>Actor: {event.actor}</span>
                        {event.resourceLabel ? <span>Resource: {event.resourceLabel}</span> : null}
                        {event.planId ? <span>Plan: {event.planId}</span> : null}
                      </div>
                    </div>
                  </div>
                </li>
              )
            })}
          </ol>
        )}

        {canLoadMore ? (
          <button
            type="button"
            disabled={loading}
            onClick={onLoadMore}
            className="mx-auto mt-5 block rounded-md border border-border bg-card px-4 py-2 text-sm font-medium disabled:opacity-40"
          >
            {loading ? "Loading…" : "Load older events"}
          </button>
        ) : null}
      </div>
    </section>
  )
}
