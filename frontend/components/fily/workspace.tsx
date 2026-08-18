"use client"

import { useMemo, useState } from "react"
import { filyApi } from "@/lib/fily-api"
import type { ConnectedAccount, JobApplication, MailboxFolder } from "@/lib/fily-api"
import { Sidebar } from "./sidebar"
import { AskBar } from "./ask-bar"
import { ApplicationList } from "./application-list"
import { ApplicationDetail } from "./application-detail"

export function Workspace({
  folders,
  accounts,
  applications,
}: {
  folders: MailboxFolder[]
  accounts: ConnectedAccount[]
  applications: JobApplication[]
}) {
  const [selectedFolderId, setSelectedFolderId] = useState("job-applications")
  const [selectedId, setSelectedId] = useState<string | null>(applications[0]?.id ?? null)
  const [query, setQuery] = useState("")
  const [panelCollapsed, setPanelCollapsed] = useState(false)
  const [answer, setAnswer] = useState<string | null>(null)
  const [asking, setAsking] = useState(false)

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return applications
    return applications.filter((a) =>
      [a.company, a.position, a.nextAction, a.stage].join(" ").toLowerCase().includes(q),
    )
  }, [applications, query])

  const selected = useMemo(
    () => applications.find((a) => a.id === selectedId) ?? null,
    [applications, selectedId],
  )
  async function ask(question: string) {
    const trimmed = question.trim()
    if (!trimmed || asking) return
    setAsking(true)
    try {
      const result = await filyApi.askFily(trimmed)
      setAnswer(result.answer)
    } catch (error) {
      setAnswer(error instanceof Error ? error.message : "Fily could not answer that question.")
    } finally {
      setAsking(false)
    }
  }


  return (
    <div className="flex h-screen w-full overflow-hidden bg-background text-foreground">
      <Sidebar
        folders={folders}
        accounts={accounts}
        selectedFolderId={selectedFolderId}
        onSelectFolder={setSelectedFolderId}
      />

      <div className="flex min-w-0 flex-1 flex-col">
        <AskBar value={query} onChange={setQuery} onSubmit={ask} />
        {(answer || asking) && (
          <div
            className="border-b border-border bg-secondary/40 px-5 py-3 text-sm text-foreground"
            role="status"
            aria-live="polite"
          >
            {asking ? "Fily is searching your local index…" : answer}
          </div>
        )}
        <div className="flex min-h-0 flex-1">
          <ApplicationList
            applications={filtered}
            selectedId={selectedId}
            onSelect={setSelectedId}
            query={query}
          />
          <ApplicationDetail
            application={selected}
            collapsed={panelCollapsed}
            onToggle={() => setPanelCollapsed((v) => !v)}
            api={filyApi}
          />
        </div>
      </div>
    </div>
  )
}
