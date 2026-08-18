export type OpaqueId = string

export type ProviderKind = "gmail" | "imap" | "yahoo" | "icloud"
export type AccountStatus = "connected" | "syncing" | "attention" | "offline"
export type PlanRisk = "low" | "medium" | "high"
export type AccountConnectionPhase =
  | "awaiting_authorization"
  | "capturing_credentials"
  | "connecting"
  | "connected"
  | "cancelled"
  | "failed"
export type SyncPhase = "starting" | "syncing" | "complete" | "more_available" | "failed"
export interface ImapPublicConfiguration {
  imapHost: string
  imapPort: number
  smtpHost: string
  smtpPort: number
  username: string
}

export interface AccountConnectionInput {
  provider: ProviderKind
  email?: string
  imapConfiguration?: ImapPublicConfiguration
}

export type PlanStatus = "pending" | "approved" | "rejected" | "executed" | "expired" | "failed"
export type LegacyMigrationState = "notFound" | "ready" | "completed"

export interface LegacyMigrationStatus {
  state: LegacyMigrationState
  accounts: number
  messages: number
  skipped: number
}


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
/**
 * Public state for a Rust-owned connection flow. The identifier is opaque and
 * authorizationUrl is informational; authorization is opened by the Rust core.
 */
export interface AccountConnection {
  connectionId: OpaqueId
  provider: ProviderKind
  phase: AccountConnectionPhase
  authorizationUrl?: string | null
  account?: ConnectedAccount | null
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
  accountId: OpaqueId
  phase: SyncPhase
  processed: number
  total?: number | null
  hasMore: boolean
}

export interface SyncProgress extends SyncResult {
  statusMessage?: string | null
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
  beginAccountConnection(input: AccountConnectionInput): Promise<AccountConnection>
  getAccountConnectionStatus(connectionId: OpaqueId): Promise<AccountConnection>
  completeAccountConnection(connectionId: OpaqueId): Promise<AccountConnection>
  startAccountSync(accountId: OpaqueId): Promise<SyncResult>
  onSyncProgress(listener: (progress: SyncProgress) => void): Promise<() => void>
  requestAccountDisconnect(accountId: OpaqueId): Promise<AgentPlan>
  getLegacyMigrationStatus(): Promise<LegacyMigrationStatus>
  migrateLegacyData(): Promise<LegacyMigrationStatus>
  getAgentPlans(): Promise<AgentPlan[]>
  approveAgentPlan(planId: OpaqueId, confirmation: string): Promise<AgentPlan>
  executeAgentPlan(planId: OpaqueId): Promise<PlanExecution>
  getAuditHistory(limit?: number, cursor?: string): Promise<AuditPage>
}
