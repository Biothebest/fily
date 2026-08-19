"use client"

import { useEffect, useState } from "react"
import { Archive, Check, RotateCcw, Send, ShieldCheck, X } from "lucide-react"
import type { AgentAnswer, ArchiveCase, LearnedRule, ReviewQueueKind, ReviewRecord, RuleChangePreview, RuleInput } from "@/lib/fily-api"
import { filyApi } from "@/lib/fily-api"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

const queues: Array<{ id: ReviewQueueKind; label: string }> = [
  { id: "needs_decision", label: "Needs decision" },
  { id: "suggested_action", label: "Suggested actions" },
  { id: "duplicate", label: "Duplicates" },
  { id: "case", label: "Cases" },
]

export function AgentWorkspace() {
  const [queue, setQueue] = useState<ReviewQueueKind>("needs_decision")
  const [items, setItems] = useState<ReviewRecord[]>([])
  const [rules, setRules] = useState<LearnedRule[]>([])
  const [archives, setArchives] = useState<ArchiveCase[]>([])
  const [question, setQuestion] = useState("")
  const [answer, setAnswer] = useState<AgentAnswer | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [ruleDraft, setRuleDraft] = useState<RuleInput>({
    name: "",
    conditions: [],
    actions: [],
    reason: "",
    confidenceThreshold: 0.9,
    approvalMode: "always_ask",
    schedule: "manual",
  })
  const [editingRuleId, setEditingRuleId] = useState<string | undefined>()
  const [rulePreview, setRulePreview] = useState<RuleChangePreview | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    setError(null)
    Promise.all([filyApi.listReviewQueue(queue), filyApi.listRules(), filyApi.listArchives()])
      .then(([nextItems, nextRules, nextArchives]) => {
        if (!active) return
        setItems(nextItems)
        setRules(nextRules)
        setArchives(nextArchives)
      })
      .catch((cause) => active && setError(cause instanceof Error ? cause.message : "Fily could not load this workspace."))
    return () => { active = false }
  }, [queue])

  async function ask() {
    if (!question.trim() || busy) return
    setBusy("ask")
    setError(null)
    try { setAnswer(await filyApi.askAgent(question)) }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Fily could not answer.") }
    finally { setBusy(null) }
  }

  async function decide(item: ReviewRecord, decision: "approve" | "reject") {
    setBusy(item.id)
    setError(null)
    try {
      const updated = await filyApi.decideReviewItem(item.id, decision)
      setItems((current) => current.map((entry) => entry.id === updated.id ? updated : entry))
    } catch (cause) { setError(cause instanceof Error ? cause.message : "The decision was not saved.") }
    finally { setBusy(null) }
  }

  async function undo(item: ReviewRecord) {
    setBusy(item.id)
    try {
      const updated = await filyApi.undoReviewItem(item.id)
      setItems((current) => current.map((entry) => entry.id === updated.id ? updated : entry))
    } catch (cause) { setError(cause instanceof Error ? cause.message : "This change could not be undone.") }
    finally { setBusy(null) }
  }

  function editRule(rule?: LearnedRule) {
    setEditingRuleId(rule?.id)
    setRulePreview(null)
    setRuleDraft(rule ? {
      name: rule.name,
      conditions: rule.conditions,
      actions: rule.actions,
      reason: rule.reason,
      confidenceThreshold: rule.confidenceThreshold,
      approvalMode: rule.approvalMode,
      schedule: rule.schedule,
    } : {
      name: "",
      conditions: [],
      actions: [],
      reason: "",
      confidenceThreshold: 0.9,
      approvalMode: "always_ask",
      schedule: "manual",
    })
  }

  async function previewRule(deleting = false) {
    setBusy("rule")
    setError(null)
    try {
      setRulePreview(await filyApi.previewRuleChange(ruleDraft, editingRuleId, deleting))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Fily could not preview that rule.")
    } finally {
      setBusy(null)
    }
  }

  async function confirmRule() {
    if (!rulePreview) return
    setBusy("rule")
    try {
      const saved = await filyApi.confirmRuleChange(rulePreview, rulePreview.requiredConfirmation)
      setRules((current) => rulePreview.operation === "delete"
        ? current.filter((rule) => rule.id !== saved.id)
        : [...current.filter((rule) => rule.id !== saved.id), saved])
      editRule()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Fily could not apply that rule.")
    } finally {
      setBusy(null)
    }
  }

  return (
    <main className="min-w-0 flex-1 overflow-y-auto bg-background" aria-labelledby="agent-heading">
      <header className="border-b bg-card px-6 py-5">
        <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Local records steward</p>
        <h1 id="agent-heading" className="mt-1 text-xl font-semibold">Ask, review, then act</h1>
        <form className="mt-4 flex max-w-3xl gap-2" onSubmit={(event) => { event.preventDefault(); void ask() }}>
          <label htmlFor="agent-question" className="sr-only">Ask Fily about your records</label>
          <input id="agent-question" value={question} onChange={(event) => setQuestion(event.target.value)} placeholder="Ask about a person, vendor, deadline, or case…" className="min-w-0 flex-1 rounded-md border bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring" />
          <Button disabled={!question.trim() || busy === "ask"}><Send className="size-4" />{busy === "ask" ? "Checking…" : "Ask Fily"}</Button>
        </form>
      </header>

      <div className="space-y-6 p-6">
        {error ? <div role="alert" className="rounded-md border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">{error}</div> : null}
        {answer ? <section className="max-w-4xl border-l-2 border-primary pl-4" aria-labelledby="answer-heading">
          <div className="flex items-center gap-2"><ShieldCheck className="size-4 text-primary" /><h2 id="answer-heading" className="font-semibold">Fily’s answer</h2><span className="text-xs text-muted-foreground">{Math.round(answer.confidence * 100)}% confidence</span></div>
          <p className="mt-2 whitespace-pre-wrap text-sm leading-6">{answer.answer}</p>
          <h3 className="mt-4 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Sources</h3>
          <ul className="mt-2 space-y-2">{answer.citations.map((citation) => <li key={`${citation.sourceKind}-${citation.recordId}`} className="rounded-md border bg-card p-3 text-sm"><strong>{citation.title}</strong><p className="mt-1 text-muted-foreground">{citation.excerpt}</p></li>)}</ul>
          {answer.plan ? <p className="mt-3 rounded-md bg-accent px-3 py-2 text-sm"><strong>Suggested, not executed:</strong> {answer.plan.summary}. Review every affected record in Agent plans.</p> : null}
        </section> : null}

        <section aria-labelledby="review-heading">
          <div className="flex items-end justify-between gap-4"><div><h2 id="review-heading" className="text-lg font-semibold">Review queues</h2><p className="text-sm text-muted-foreground">Suggestions remain separate from executed changes.</p></div></div>
          <div className="mt-3 flex gap-1 overflow-x-auto border-b" role="tablist" aria-label="Review queues">{queues.map((entry) => <button key={entry.id} role="tab" aria-selected={queue === entry.id} onClick={() => setQueue(entry.id)} className={cn("whitespace-nowrap border-b-2 px-3 py-2 text-sm", queue === entry.id ? "border-primary font-medium text-foreground" : "border-transparent text-muted-foreground hover:text-foreground")}>{entry.label}</button>)}</div>
          {items.length === 0 ? <div className="py-10 text-center"><Check className="mx-auto size-5 text-muted-foreground" /><p className="mt-2 text-sm font-medium">Queue reviewed</p><p className="text-sm text-muted-foreground">New findings will appear after local processing.</p></div> : <ul className="divide-y">{items.map((item) => <li key={item.id} className="py-4"><div className="flex flex-wrap items-start justify-between gap-3"><div className="min-w-0"><div className="flex items-center gap-2"><h3 className="font-medium">{item.title}</h3><span className={cn("rounded-full px-2 py-0.5 text-xs", item.status === "executed" ? "bg-info-muted text-info" : "bg-muted text-muted-foreground")}>{item.status === "suggested" ? "Suggestion" : item.status}</span></div><p className="mt-1 text-sm text-muted-foreground">{item.reason}</p><p className="mt-2 text-xs text-muted-foreground">{item.affectedRecords.length} affected records · {Math.round(item.confidence * 100)}% confidence</p></div><div className="flex gap-2">{item.status === "suggested" ? <><Button size="sm" variant="outline" disabled={busy === item.id} onClick={() => void decide(item, "reject")}><X className="size-4" />Reject</Button><Button size="sm" disabled={busy === item.id} onClick={() => void decide(item, "approve")}><Check className="size-4" />Approve</Button></> : item.status === "executed" && item.reversible ? <Button size="sm" variant="outline" disabled={busy === item.id} onClick={() => void undo(item)}><RotateCcw className="size-4" />Undo</Button> : null}</div></div></li>)}</ul>}
        </section>

        <div className="grid gap-6 xl:grid-cols-2">
          <section aria-labelledby="rules-heading">
            <div className="flex items-center justify-between gap-3">
              <div><h2 id="rules-heading" className="text-lg font-semibold">Rules</h2><p className="text-sm text-muted-foreground">Bounded autonomy; sends and permanent deletes always require you.</p></div>
              <Button type="button" variant="outline" onClick={() => editRule()}>New rule</Button>
            </div>
            <form className="mt-3 space-y-2 rounded-md border p-3" onSubmit={(event) => { event.preventDefault(); void previewRule() }}>
              <input aria-label="Rule name" required value={ruleDraft.name} onChange={(event) => setRuleDraft((current) => ({ ...current, name: event.target.value }))} placeholder="Rule name" className="w-full rounded-md border bg-background px-3 py-2 text-sm" />
              <input aria-label="Rule conditions" required value={ruleDraft.conditions.join("; ")} onChange={(event) => setRuleDraft((current) => ({ ...current, conditions: event.target.value.split(";").map((value) => value.trim()).filter(Boolean) }))} placeholder="Conditions, separated by semicolons" className="w-full rounded-md border bg-background px-3 py-2 text-sm" />
              <input aria-label="Rule actions" required value={ruleDraft.actions.join("; ")} onChange={(event) => setRuleDraft((current) => ({ ...current, actions: event.target.value.split(";").map((value) => value.trim()).filter(Boolean) }))} placeholder="Actions, separated by semicolons" className="w-full rounded-md border bg-background px-3 py-2 text-sm" />
              <input aria-label="Rule reason" required value={ruleDraft.reason} onChange={(event) => setRuleDraft((current) => ({ ...current, reason: event.target.value }))} placeholder="Why this rule exists" className="w-full rounded-md border bg-background px-3 py-2 text-sm" />
              <div className="flex flex-wrap gap-2">
                <Button disabled={busy === "rule"}>{editingRuleId ? "Preview update" : "Preview rule"}</Button>
                {editingRuleId ? <Button type="button" variant="outline" disabled={busy === "rule"} onClick={() => void previewRule(true)}>Preview delete</Button> : null}
              </div>
              {rulePreview ? <div className="rounded-md bg-accent p-3 text-sm"><strong>{rulePreview.summary}</strong><p className="mt-1 text-muted-foreground">Confirmation required: {rulePreview.requiredConfirmation}</p><Button type="button" className="mt-2" disabled={busy === "rule"} onClick={() => void confirmRule()}>Confirm {rulePreview.operation}</Button></div> : null}
            </form>
            <ul className="mt-3 divide-y border-y">{rules.map((rule) => <li key={rule.id} className="py-3"><div className="flex items-center justify-between gap-3"><strong className="text-sm">{rule.name}</strong><Button type="button" variant="ghost" onClick={() => editRule(rule)}>Edit</Button></div><p className="mt-1 text-sm">When {rule.conditions.join("; ")} → {rule.actions.join("; ")}</p><p className="mt-1 text-xs text-muted-foreground">{rule.reason} · {rule.approvalMode.replaceAll("_", " ")} at {Math.round(rule.confidenceThreshold * 100)}%</p></li>)}</ul>
          </section>
          <section aria-labelledby="archives-heading"><h2 id="archives-heading" className="text-lg font-semibold">Archives</h2><p className="text-sm text-muted-foreground">Employee, vendor, and case records assembled from cited sources.</p><ul className="mt-3 divide-y border-y">{archives.map((item) => <li key={item.id} className="flex gap-3 py-3"><Archive className="mt-0.5 size-4 text-muted-foreground" /><div><strong className="text-sm">{item.title}</strong><p className="text-sm text-muted-foreground">{item.summary}</p><p className="mt-1 text-xs text-muted-foreground">{item.kind} · {item.citations.length} records</p></div></li>)}</ul></section>
        </div>
      </div>
    </main>
  )
}
