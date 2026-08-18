"use client"

import { useEffect, useState } from "react"
import { filyApi } from "@/lib/fily-api"
import type {
  AgentPlan,
  AuditEvent,
  BootstrapData,
  OpaqueId,
  SanitizedMessage,
  SearchHit,
} from "@/lib/fily-api"
import { AccountSettings } from "./account-settings"
import { AgentPlanApproval } from "./agent-plan-approval"
import { AuditHistory } from "./audit-history"
import { InboxScreen } from "./inbox-screen"
import { MessageViewer } from "./message-viewer"
import { SearchScreen } from "./search-screen"
import { Sidebar, type WorkspaceScreen } from "./sidebar"

function messageFor(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback
}

export function Workspace({ data }: { data: BootstrapData }) {
  const [screen, setScreen] = useState<WorkspaceScreen>("inbox")
  const [workspaceData, setWorkspaceData] = useState(data)
  const [selectedFolderId, setSelectedFolderId] = useState<OpaqueId | null>(null)
  const [selectedMessageId, setSelectedMessageId] = useState<OpaqueId | null>(data.messages[0]?.id ?? null)
  const [message, setMessage] = useState<SanitizedMessage | null>(null)
  const [messageLoading, setMessageLoading] = useState(false)
  const [messageError, setMessageError] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState("")
  const [searchResults, setSearchResults] = useState<SearchHit[]>([])
  const [searching, setSearching] = useState(false)
  const [searchError, setSearchError] = useState<string | null>(null)
  const [plans, setPlans] = useState<AgentPlan[]>([])
  const [plansError, setPlansError] = useState<string | null>(null)
  const [busyPlanId, setBusyPlanId] = useState<OpaqueId | null>(null)
  const [disconnectingId, setDisconnectingId] = useState<OpaqueId | null>(null)
  const [syncingId, setSyncingId] = useState<OpaqueId | null>(null)
  const [syncNotice, setSyncNotice] = useState<string | null>(null)
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([])
  const [auditCursor, setAuditCursor] = useState<string | null>(null)
  const [auditLoading, setAuditLoading] = useState(false)
  const [auditError, setAuditError] = useState<string | null>(null)

  async function openMessage(id: OpaqueId, navigate = false) {
    setSelectedMessageId(id)
    setMessageLoading(true)
    setMessageError(null)
    if (navigate) setScreen("inbox")
    try {
      setMessage(await filyApi.getMessage(id))
    } catch (error) {
      setMessage(null)
      setMessageError(messageFor(error, "Fily could not open this message."))
    } finally {
      setMessageLoading(false)
    }
  }

  useEffect(() => {
    const initialMessageId = data.messages[0]?.id
    if (initialMessageId) void openMessage(initialMessageId)

    let cancelled = false
    filyApi
      .getAgentPlans()
      .then((loadedPlans) => {
        if (!cancelled) setPlans(loadedPlans)
      })
      .catch((error) => {
        if (!cancelled) setPlansError(messageFor(error, "Fily could not load agent plans."))
      })
    return () => {
      cancelled = true
    }
  }, [data.messages])

  async function search() {
    const query = searchQuery.trim()
    if (!query || searching) return
    setSearching(true)
    setSearchError(null)
    try {
      setSearchResults(await filyApi.searchMessages(query, 50))
    } catch (error) {
      setSearchResults([])
      setSearchError(messageFor(error, "Fily could not search the local index."))
    } finally {
      setSearching(false)
    }
  }

  async function startSync(accountId: OpaqueId) {
    if (syncingId) return
    setSyncingId(accountId)
    setSyncNotice(null)
    try {
      const result = await filyApi.startAccountSync(accountId)
      const completedNotice = result.hasMore
        ? `Indexed ${result.changed.toLocaleString()} changes. More remain; the trusted core retained its private cursor.`
        : `Sync complete. Indexed ${result.changed.toLocaleString()} changes.`
      setSyncNotice(completedNotice)
      try {
        setWorkspaceData(await filyApi.getBootstrap(50))
      } catch {
        setSyncNotice(`${completedNotice} Reopen the workspace to refresh its message list.`)
      }
    } catch (error) {
      setSyncNotice(messageFor(error, "Fily could not sync this account."))
    } finally {
      setSyncingId(null)
    }
  }

  async function requestDisconnect(accountId: OpaqueId) {
    if (disconnectingId) return
    setDisconnectingId(accountId)
    setPlansError(null)
    try {
      const plan = await filyApi.requestAccountDisconnect(accountId)
      setPlans((current) => [plan, ...current.filter((item) => item.id !== plan.id)])
      setScreen("plans")
    } catch (error) {
      setPlansError(messageFor(error, "Fily could not prepare the disconnect preview."))
      setScreen("plans")
    } finally {
      setDisconnectingId(null)
    }
  }

  async function approvePlan(planId: OpaqueId, confirmation: string) {
    if (busyPlanId) return
    setBusyPlanId(planId)
    setPlansError(null)
    try {
      const approved = await filyApi.approveAgentPlan(planId, confirmation)
      setPlans((current) => current.map((plan) => (plan.id === approved.id ? approved : plan)))
    } catch (error) {
      setPlansError(messageFor(error, "The plan was not approved."))
    } finally {
      setBusyPlanId(null)
    }
  }

  async function executePlan(planId: OpaqueId) {
    if (busyPlanId) return
    setBusyPlanId(planId)
    setPlansError(null)
    try {
      const execution = await filyApi.executeAgentPlan(planId)
      setPlans((current) =>
        current.map((plan) => (plan.id === planId ? { ...plan, status: execution.status } : plan)),
      )
    } catch (error) {
      setPlansError(messageFor(error, "The approved plan was not executed."))
    } finally {
      setBusyPlanId(null)
    }
  }

  async function loadAudit(append: boolean) {
    if (auditLoading) return
    setAuditLoading(true)
    setAuditError(null)
    try {
      const page = await filyApi.getAuditHistory(50, append ? auditCursor ?? undefined : undefined)
      setAuditEvents((current) => (append ? [...current, ...page.events] : page.events))
      setAuditCursor(page.nextCursor ?? null)
    } catch (error) {
      setAuditError(messageFor(error, "Fily could not load audit history."))
    } finally {
      setAuditLoading(false)
    }
  }

  function navigate(nextScreen: WorkspaceScreen) {
    setScreen(nextScreen)
    if (nextScreen === "audit" && auditEvents.length === 0 && !auditLoading) void loadAudit(false)
  }

  const pendingPlanCount = plans.filter((plan) => plan.status === "pending").length

  return (
    <main className="flex h-screen w-full overflow-hidden bg-background text-foreground">
      <Sidebar
        accounts={workspaceData.accounts}
        screen={screen}
        pendingPlanCount={pendingPlanCount}
        onNavigate={navigate}
      />
      {screen === "inbox" ? (
        <div className="flex min-w-0 flex-1">
          <InboxScreen
            folders={workspaceData.folders}
            messages={workspaceData.messages}
            selectedFolderId={selectedFolderId}
            selectedMessageId={selectedMessageId}
            onSelectFolder={setSelectedFolderId}
            onSelectMessage={(id) => void openMessage(id)}
          />
          <MessageViewer message={message} loading={messageLoading} error={messageError} />
        </div>
      ) : null}
      {screen === "search" ? (
        <SearchScreen
          query={searchQuery}
          results={searchResults}
          searching={searching}
          error={searchError}
          onQueryChange={setSearchQuery}
          onSearch={() => void search()}
          onOpenMessage={(id) => void openMessage(id, true)}
        />
      ) : null}
      {screen === "settings" ? (
        <AccountSettings
          accounts={workspaceData.accounts}
          syncingId={syncingId}
          disconnectingId={disconnectingId}
          syncNotice={syncNotice}
          onStartSync={(id) => void startSync(id)}
          onRequestDisconnect={(id) => void requestDisconnect(id)}
        />
      ) : null}
      {screen === "plans" ? (
        <AgentPlanApproval
          plans={plans}
          busyPlanId={busyPlanId}
          error={plansError}
          onApprove={approvePlan}
          onExecute={executePlan}
        />
      ) : null}
      {screen === "audit" ? (
        <AuditHistory
          events={auditEvents}
          loading={auditLoading}
          error={auditError}
          canLoadMore={Boolean(auditCursor)}
          onLoadMore={() => void loadAudit(true)}
        />
      ) : null}
    </main>
  )
}
