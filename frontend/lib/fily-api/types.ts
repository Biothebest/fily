export type OpaqueId = string

export type ProviderKind = "gmail" | "imap" | "yahoo" | "icloud"
export type AccountStatus = "connected" | "syncing" | "attention" | "offline"
export type PlanRisk = "low" | "medium" | "high"
export type PlanStatus = "pending" | "approved" | "rejected" | "executed" | "expired" | "failed"

export interface MailboxFolder {
  id: OpaqueId
  label: string
  count?: number
  unreadCount?: number
}

export interface ConnectedAccount {
  id: OpaqueId
  provider: ProviderKind
  email: string
  displayName?: string
  status: AccountStatus
  lastSyncedAt?: string | null
  statusMessage?: string | null
}

export interface MailAddress {
  name?: string | null
  address: string
}

export interface MessageSummary {
  id: OpaqueId
  threadId: OpaqueId
  accountId: OpaqueId
  folderId: OpaqueId
  sender: MailAddress
  subject: string
  snippet: string
  receivedAt: string
  unread: boolean
  starred: boolean
  hasAttachments: boolean
}

/**
 * A message representation prepared by the Rust core for display. It deliberately
 * contains no HTML, remote URLs, raw headers, filesystem paths, or provider data.
 */
export interface SanitizedMessage extends MessageSummary {
  recipients: MailAddress[]
  cc: MailAddress[]
  bodyText: string
  remoteContentBlocked: boolean
  attachments: SafeAttachment[]
}

export interface SafeAttachment {
  id: OpaqueId
  filename: string
  mediaType: string
  sizeBytes: number
}

export interface SearchHit {
  message: MessageSummary
  matchedSnippet: string
}

export interface BootstrapData {
  folders: MailboxFolder[]
  accounts: ConnectedAccount[]
  messages: MessageSummary[]
}


export interface PlanStep {
  label: string
  detail: string
}

export interface PlanPreviewField {
  label: string
  value: string
}

export interface AgentPlan {
  id: OpaqueId
  action: string
  summary: string
  rationale: string
  risk: PlanRisk
  status: PlanStatus
  steps: PlanStep[]
  preview: PlanPreviewField[]
  requiredConfirmation: string
  createdAt: string
  expiresAt: string
}

export interface PlanExecution {
  planId: OpaqueId
  status: PlanStatus
  completedAt?: string | null
  summary: string
}

export interface AuditEvent {
  id: OpaqueId
  occurredAt: string
  actor: "user" | "agent" | "system"
  action: string
  outcome: "allowed" | "denied" | "failed"
  summary: string
  resourceLabel?: string | null
  planId?: OpaqueId | null
}

export interface SyncResult {
  changed: number
  hasMore: boolean
  nextCursor?: string | null
}

export interface AuditPage {
  events: AuditEvent[]
  nextCursor?: string | null
}

export interface FilyApi {
  getBootstrap(messageLimit: number): Promise<BootstrapData>
  getMessage(messageId: OpaqueId): Promise<SanitizedMessage>
  searchMessages(query: string, limit?: number): Promise<SearchHit[]>
  getAccounts(): Promise<ConnectedAccount[]>
  startAccountSync(accountId: OpaqueId): Promise<SyncResult>
  requestAccountDisconnect(accountId: OpaqueId): Promise<AgentPlan>
  getAgentPlans(): Promise<AgentPlan[]>
  approveAgentPlan(planId: OpaqueId, confirmation: string): Promise<AgentPlan>
  executeAgentPlan(planId: OpaqueId): Promise<PlanExecution>
  getAuditHistory(limit?: number, cursor?: string): Promise<AuditPage>
}
