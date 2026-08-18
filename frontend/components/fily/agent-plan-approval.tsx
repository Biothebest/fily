"use client"

import { AlertTriangle, Bot, CheckCircle2, Clock3, Play, ShieldAlert } from "lucide-react"
import { useEffect, useState } from "react"
import { cn } from "@/lib/utils"
import type { AgentPlan, OpaqueId } from "@/lib/fily-api"

const RISK_STYLES: Record<AgentPlan["risk"], string> = {
  low: "bg-secondary text-secondary-foreground",
  medium: "bg-info-muted text-info",
  high: "bg-destructive/10 text-destructive",
}

export function AgentPlanApproval({
  plans,
  busyPlanId,
  error,
  onApprove,
  onExecute,
}: {
  plans: AgentPlan[]
  busyPlanId: OpaqueId | null
  error: string | null
  onApprove: (id: OpaqueId, confirmation: string) => Promise<void>
  onExecute: (id: OpaqueId) => Promise<void>
}) {
  const [selectedId, setSelectedId] = useState<OpaqueId | null>(plans[0]?.id ?? null)
  const [confirmation, setConfirmation] = useState("")
  const selected = plans.find((plan) => plan.id === selectedId) ?? plans[0] ?? null

  useEffect(() => {
    if (selected && selected.id !== selectedId) setSelectedId(selected.id)
  }, [selected, selectedId])

  useEffect(() => {
    setConfirmation("")
  }, [selected?.id, selected?.status])

  if (!selected) {
    return (
      <section className="flex h-full flex-1 items-center justify-center p-8 text-center">
        <div>
          <CheckCircle2 className="mx-auto size-7 text-primary" />
          <h1 className="mt-3 font-semibold">No agent plans</h1>
          <p className="mt-1 text-sm text-muted-foreground">Proposed actions will appear here before anything changes.</p>
        </div>
      </section>
    )
  }

  const matchesConfirmation = confirmation === selected.requiredConfirmation
  const isBusy = busyPlanId === selected.id

  return (
    <section className="flex h-full min-w-0 flex-1" aria-labelledby="plans-heading">
      <aside className="w-80 shrink-0 overflow-y-auto border-r border-border bg-card">
        <header className="border-b border-border px-5 py-4">
          <h1 id="plans-heading" className="font-semibold">Agent plans</h1>
          <p className="mt-0.5 text-xs text-muted-foreground">Review before Fily acts</p>
        </header>
        <ol>
          {plans.map((plan) => (
            <li key={plan.id}>
              <button
                type="button"
                onClick={() => setSelectedId(plan.id)}
                className={cn(
                  "w-full border-b border-border p-4 text-left hover:bg-accent/50",
                  plan.id === selected.id && "bg-info-muted/40",
                )}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate text-sm font-medium">{plan.action}</span>
                  <span className={cn("rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase", RISK_STYLES[plan.risk])}>
                    {plan.risk}
                  </span>
                </div>
                <p className="mt-1 line-clamp-2 text-xs text-muted-foreground">{plan.summary}</p>
                <p className="mt-2 flex items-center gap-1 text-[10px] uppercase tracking-wide text-muted-foreground">
                  <Clock3 className="size-3" /> {plan.status}
                </p>
              </button>
            </li>
          ))}
        </ol>
      </aside>

      <div className="min-w-0 flex-1 overflow-y-auto">
        <div className="mx-auto max-w-3xl px-8 py-8">
          <div className="flex items-start justify-between gap-5">
            <div>
              <p className="flex items-center gap-1.5 text-xs font-medium text-primary"><Bot className="size-4" /> Proposed by Fily</p>
              <h2 className="mt-2 text-xl font-semibold">{selected.action}</h2>
              <p className="mt-2 text-sm leading-relaxed text-muted-foreground">{selected.summary}</p>
            </div>
            <span className={cn("rounded-full px-3 py-1 text-xs font-semibold uppercase", RISK_STYLES[selected.risk])}>
              {selected.risk} risk
            </span>
          </div>

          <section className="mt-7 rounded-xl border border-border bg-card p-5">
            <h3 className="text-sm font-semibold">Why Fily proposed this</h3>
            <p className="mt-2 text-sm leading-relaxed text-muted-foreground">{selected.rationale}</p>
          </section>

          <section className="mt-4 rounded-xl border border-border bg-card p-5">
            <h3 className="text-sm font-semibold">Exact action preview</h3>
            <dl className="mt-3 divide-y divide-border">
              {selected.preview.map((field) => (
                <div key={`${field.label}-${field.value}`} className="grid grid-cols-[9rem_1fr] gap-3 py-2.5 text-sm">
                  <dt className="text-muted-foreground">{field.label}</dt>
                  <dd className="whitespace-pre-wrap break-words font-medium">{field.value}</dd>
                </div>
              ))}
            </dl>
          </section>

          <section className="mt-4 rounded-xl border border-border bg-card p-5">
            <h3 className="text-sm font-semibold">Steps</h3>
            <ol className="mt-3 space-y-3">
              {selected.steps.map((step, index) => (
                <li key={`${step.label}-${index}`} className="flex gap-3 text-sm">
                  <span className="flex size-6 shrink-0 items-center justify-center rounded-full bg-secondary text-xs font-medium">
                    {index + 1}
                  </span>
                  <div><p className="font-medium">{step.label}</p><p className="mt-0.5 text-xs text-muted-foreground">{step.detail}</p></div>
                </li>
              ))}
            </ol>
          </section>

          {error ? <p className="mt-4 rounded-lg border border-destructive/30 p-3 text-sm text-destructive">{error}</p> : null}

          {selected.status === "pending" ? (
            <section className="mt-6 rounded-xl border border-destructive/30 bg-destructive/5 p-5">
              <div className="flex gap-3">
                {selected.risk === "high" ? <ShieldAlert className="size-5 shrink-0 text-destructive" /> : <AlertTriangle className="size-5 shrink-0 text-primary" />}
                <div className="min-w-0 flex-1">
                  <h3 className="text-sm font-semibold">Explicit confirmation required</h3>
                  <p className="mt-1 text-xs text-muted-foreground">
                    Type <strong className="text-foreground">{selected.requiredConfirmation}</strong> to approve this exact plan. Approval does not silently authorize a different action.
                  </p>
                  <input
                    type="text"
                    value={confirmation}
                    maxLength={256}
                    autoComplete="off"
                    spellCheck={false}
                    onChange={(event) => setConfirmation(event.target.value)}
                    className="mt-3 h-10 w-full rounded-md border border-input bg-card px-3 text-sm outline-none focus:ring-2 focus:ring-ring/20"
                    aria-label="Plan confirmation phrase"
                  />
                  <button
                    type="button"
                    disabled={!matchesConfirmation || isBusy}
                    onClick={() => onApprove(selected.id, confirmation)}
                    className="mt-3 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground disabled:opacity-40"
                  >
                    {isBusy ? "Approving…" : "Approve exact plan"}
                  </button>
                </div>
              </div>
            </section>
          ) : selected.status === "approved" ? (
            <section className="mt-6 rounded-xl border border-primary/25 bg-info-muted/40 p-5">
              <h3 className="text-sm font-semibold">Plan approved</h3>
              <p className="mt-1 text-xs text-muted-foreground">Execute only when you are ready. The Rust core revalidates the approved plan before acting.</p>
              <button
                type="button"
                disabled={isBusy}
                onClick={() => onExecute(selected.id)}
                className="mt-3 flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground disabled:opacity-40"
              >
                <Play className="size-3.5" /> {isBusy ? "Executing…" : "Execute approved plan"}
              </button>
            </section>
          ) : (
            <p className="mt-6 rounded-xl border border-border bg-secondary/30 p-4 text-sm">
              This plan is <strong>{selected.status}</strong> and cannot be approved again.
            </p>
          )}

          <p className="mt-4 text-[11px] text-muted-foreground">Created {selected.createdAt} · Expires {selected.expiresAt}</p>
        </div>
      </div>
    </section>
  )
}
