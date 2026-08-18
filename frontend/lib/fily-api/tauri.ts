import { invoke } from "@tauri-apps/api/core"
import { listen } from "@tauri-apps/api/event"
import type {
  AccountConnectionInput,
  AgentPlan,
  AccountConnection,
  AuditPage,
  BootstrapData,
  ConnectedAccount,
  LegacyMigrationStatus,
  FilyApi,
  OpaqueId,
  PlanExecution,
  SanitizedMessage,
  SearchHit,
  SyncProgress,
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
    if (
      typeof error === "object" &&
      error !== null &&
      "message" in error &&
      typeof error.message === "string"
    ) {
      const message = error.message.replace(/[\u0000-\u001f\u007f]/g, "").slice(0, 512)
      if (message) throw new Error(message)
    }
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
  beginAccountConnection(input: AccountConnectionInput): Promise<AccountConnection> {
    const request: Record<string, unknown> = { provider: input.provider }
    if (input.email) request.email = boundedText(input.email, "Email", 320).toLowerCase()
    if (input.imapConfiguration) {
      request.imapConfiguration = {
        imapHost: boundedText(input.imapConfiguration.imapHost, "IMAP host", 253).toLowerCase(),
        imapPort: Math.trunc(input.imapConfiguration.imapPort),
        smtpHost: boundedText(input.imapConfiguration.smtpHost, "SMTP host", 253).toLowerCase(),
        smtpPort: Math.trunc(input.imapConfiguration.smtpPort),
        username: boundedText(input.imapConfiguration.username, "Username", 320),
      }
    }
    return command("begin_account_connection", request)
  }

  getAccountConnectionStatus(connectionId: OpaqueId): Promise<AccountConnection> {
    return command("account_connection_status", {
      connectionId: opaqueId(connectionId, "Connection"),
    })
  }

  completeAccountConnection(connectionId: OpaqueId): Promise<AccountConnection> {
    return command("complete_account_connection", {
      connectionId: opaqueId(connectionId, "Connection"),
    })
  }

  startAccountSync(accountId: OpaqueId): Promise<SyncResult> {
    return command("start_sync", { accountId: opaqueId(accountId, "Account") })
  }
  async onSyncProgress(listener: (progress: SyncProgress) => void): Promise<() => void> {
    return listen<SyncProgress>("account-sync-progress", (event) => listener(event.payload))
  }


  getLegacyMigrationStatus(): Promise<LegacyMigrationStatus> {
    return command("legacy_migration_status")
  }

  migrateLegacyData(): Promise<LegacyMigrationStatus> {
    return command("migrate_legacy")
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
