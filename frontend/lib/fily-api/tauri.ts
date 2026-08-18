import { invoke } from "@tauri-apps/api/core"
import type {
  AgentPlan,
  AuditPage,
  BootstrapData,
  ConnectedAccount,
  FilyApi,
  OpaqueId,
  PlanExecution,
  SanitizedMessage,
  SearchHit,
  SyncResult,
} from "./types"

const MAX_ID_LENGTH = 256
const MAX_QUERY_LENGTH = 1_000
const MAX_CONFIRMATION_LENGTH = 256
const MAX_PAGE_SIZE = 100

function opaqueId(value: string, label: string): string {
  const result = value.trim()
  if (!result || result.length > MAX_ID_LENGTH || /[\u0000-\u001f\u007f]/.test(result)) {
    throw new Error(`${label} is invalid.`)
  }
  return result
}

function boundedText(value: string, label: string, maximum: number): string {
  const result = value.trim()
  if (!result) throw new Error(`${label} is required.`)
  if (result.length > maximum) throw new Error(`${label} is too long.`)
  return result
}

function pageSize(value: number, fallback: number): number {
  if (!Number.isFinite(value)) return fallback
  return Math.max(1, Math.min(MAX_PAGE_SIZE, Math.trunc(value)))
}

async function command<T>(name: string, request?: Record<string, unknown>): Promise<T> {
  try {
    return request === undefined ? await invoke<T>(name) : await invoke<T>(name, { request })
  } catch (error) {
    if (typeof error === "string") throw new Error(error)
    if (error instanceof Error) throw error
    throw new Error("The Fily core could not complete that request.")
  }
}

class TauriFilyApi implements FilyApi {
  getBootstrap(messageLimit: number): Promise<BootstrapData> {
    return command("bootstrap", { messageLimit: pageSize(messageLimit, 50) })
  }

  getMessage(messageId: OpaqueId): Promise<SanitizedMessage> {
    return command("get_message", { messageId: opaqueId(messageId, "Message") })
  }

  searchMessages(query: string, limit = 50): Promise<SearchHit[]> {
    return command("search_messages", {
      query: boundedText(query, "Search query", MAX_QUERY_LENGTH),
      limit: pageSize(limit, 50),
    })
  }

  getAccounts(): Promise<ConnectedAccount[]> {
    return command("list_accounts")
  }
  startAccountSync(accountId: OpaqueId): Promise<SyncResult> {
    return command("start_sync", { accountId: opaqueId(accountId, "Account") })
  }


  requestAccountDisconnect(accountId: OpaqueId): Promise<AgentPlan> {
    return command("disconnect_account", { accountId: opaqueId(accountId, "Account") })
  }

  getAgentPlans(): Promise<AgentPlan[]> {
    return command("list_plans")
  }

  approveAgentPlan(planId: OpaqueId, confirmation: string): Promise<AgentPlan> {
    return command("approve_plan", {
      planId: opaqueId(planId, "Plan"),
      confirmation: boundedText(confirmation, "Confirmation", MAX_CONFIRMATION_LENGTH),
    })
  }

  executeAgentPlan(planId: OpaqueId): Promise<PlanExecution> {
    return command("execute_plan", { planId: opaqueId(planId, "Plan") })
  }

  getAuditHistory(limit = 50, cursor?: string): Promise<AuditPage> {
    const request: Record<string, unknown> = { limit: pageSize(limit, 50) }
    if (cursor) request.cursor = opaqueId(cursor, "Audit cursor")
    return command("list_audit", request)
  }
}

export const filyApi: FilyApi = new TauriFilyApi()
