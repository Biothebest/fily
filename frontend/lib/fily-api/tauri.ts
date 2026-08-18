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
  DeleteDraftResult,
  DraftInput,
  DraftPage,
  DraftView,
  FilyApi,
  OpaqueId,
  PlanExecution,
  SanitizedMessage,
  MessagePage,
  MailboxFolder,
  SearchHit,
  SyncProgress,
  SyncResult,
  SendExecution,
} from "./types"

const MAX_ID_LENGTH = 256
const MAX_QUERY_LENGTH = 1_000
const MAX_CONFIRMATION_LENGTH = 256
const MAX_PAGE_SIZE = 100
const MAX_ADDRESS_LENGTH = 320
const MAX_SUBJECT_LENGTH = 998
const MAX_BODY_LENGTH = 2_000_000

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

function draftRequest(input: DraftInput): Record<string, unknown> {
  const mailboxes = (values: DraftInput["to"], label: string) =>
    values.map((value) => ({
      name: value.name?.trim().slice(0, 320) || undefined,
      address: boundedText(value.address, label, MAX_ADDRESS_LENGTH).toLowerCase(),
    }))
  const subject = input.subject.trim().slice(0, MAX_SUBJECT_LENGTH)
  const textBody = input.textBody ?? ""
  if (textBody.length > MAX_BODY_LENGTH) throw new Error("Message body is too long.")
  return {
    accountId: opaqueId(input.accountId, "Account"),
    to: mailboxes(input.to, "To address"),
    cc: mailboxes(input.cc, "Cc address"),
    bcc: mailboxes(input.bcc, "Bcc address"),
    subject,
    textBody,
    attachmentIds: input.attachmentIds.map((id) => opaqueId(id, "Attachment")),
  }
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

  listFolders(accountId: OpaqueId): Promise<MailboxFolder[]> {
    return command("list_folders", { accountId: opaqueId(accountId, "Account") })
  }
  getMessage(accountId: OpaqueId, messageId: OpaqueId): Promise<SanitizedMessage> {
    return command("get_message", {
      accountId: opaqueId(accountId, "Account"),
      messageId: opaqueId(messageId, "Message"),
    })
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

  listMessages(accountId: OpaqueId, folderId?: OpaqueId, cursor?: string, limit = 50): Promise<MessagePage> {
    return command("list_messages", {
      accountId: opaqueId(accountId, "Account"),
      folderId: folderId ? opaqueId(folderId, "Folder") : undefined,
      cursor: cursor ? opaqueId(cursor, "Message cursor") : undefined,
      limit: pageSize(limit, 50),
    })
  }

  createDraft(input: DraftInput): Promise<DraftView> {
    return command("create_draft", draftRequest(input))
  }

  updateDraft(draftId: OpaqueId, input: DraftInput): Promise<DraftView> {
    return command("update_draft", { ...draftRequest(input), draftId: opaqueId(draftId, "Draft") })
  }

  listDrafts(accountId: OpaqueId, cursor?: string, limit = 50): Promise<DraftPage> {
    return command("list_drafts", {
      accountId: opaqueId(accountId, "Account"),
      cursor: cursor ? opaqueId(cursor, "Draft cursor") : undefined,
      limit: pageSize(limit, 50),
    })
  }

  deleteDraft(accountId: OpaqueId, draftId: OpaqueId): Promise<DeleteDraftResult> {
    return command("delete_draft", {
      accountId: opaqueId(accountId, "Account"),
      draftId: opaqueId(draftId, "Draft"),
    })
  }

  createReplyDraft(accountId: OpaqueId, messageId: OpaqueId): Promise<DraftView> {
    return command("create_reply_draft", {
      accountId: opaqueId(accountId, "Account"),
      messageId: opaqueId(messageId, "Message"),
    })
  }

  createSendPreview(accountId: OpaqueId, draftId: OpaqueId): Promise<AgentPlan> {
    return command("create_send_preview", {
      accountId: opaqueId(accountId, "Account"),
      draftId: opaqueId(draftId, "Draft"),
    })
  }

  executeSend(planId: OpaqueId): Promise<SendExecution> {
    return command("execute_send", { planId: opaqueId(planId, "Plan") })
  }
}

export const filyApi: FilyApi = new TauriFilyApi()
