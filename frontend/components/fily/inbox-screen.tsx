"use client"

import { Mail, MailPlus, Paperclip, Star } from "lucide-react"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"
import type { ConnectedAccount, MailboxFolder, MessageSummary, OpaqueId } from "@/lib/fily-api"


export function InboxScreen({
  folders,
  accounts,
  selectedAccountId,
  loading,
  error,
  hasMore,
  messages,
  selectedFolderId,
  selectedMessageId,
  onSelectFolder,
  onSelectAccount,
  onCompose,
  onLoadMore,
  onSelectMessage,
}: {
  folders: MailboxFolder[]
  accounts: ConnectedAccount[]
  selectedAccountId: OpaqueId
  loading: boolean
  error: string | null
  hasMore: boolean
  messages: MessageSummary[]
  selectedFolderId: OpaqueId | null
  selectedMessageId: OpaqueId | null
  onSelectFolder: (id: OpaqueId | null) => void
  onSelectMessage: (id: OpaqueId) => void
  onSelectAccount: (id: OpaqueId) => void
  onCompose: () => void
  onLoadMore: () => void
}) {

  return (
    <section className="flex h-full w-full max-w-2xl shrink-0 flex-col border-r border-border lg:w-[35rem]" aria-label="Mailbox">
      <header className="flex items-center gap-3 border-b border-border bg-card px-4 py-3">
        <label className="min-w-0 flex-1 text-xs font-medium text-muted-foreground">
          Connected account
          <select
            className="mt-1 h-9 w-full rounded-md border border-input bg-background px-2 text-sm text-foreground outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/30"
            value={selectedAccountId}
            onChange={(event) => onSelectAccount(event.target.value)}
          >
            {accounts.map((account) => <option key={account.id} value={account.id}>{account.email}</option>)}
          </select>
        </label>
        <Button type="button" onClick={onCompose}><MailPlus /> Compose</Button>
      </header>
      <div className="flex min-h-0 flex-1">
      <div className="w-44 shrink-0 border-r border-border bg-secondary/20 p-3 sm:w-52">
        <nav aria-label="Inbox folders">
          <button
            type="button"
            onClick={() => onSelectFolder(null)}
            className={cn(
              "flex w-full items-center justify-between rounded-md px-2 py-1.5 text-left text-sm",
              selectedFolderId === null ? "bg-accent font-medium" : "text-muted-foreground hover:bg-accent/60",
            )}
          >
            <span>All messages</span>
            <span className="text-xs tabular-nums">{messages.length}</span>
          </button>
          {folders.map((folder) => (
            <button
              key={folder.id}
              type="button"
              onClick={() => onSelectFolder(folder.id)}
              className={cn(
                "mt-0.5 flex w-full items-center justify-between rounded-md px-2 py-1.5 text-left text-sm",
                selectedFolderId === folder.id
                  ? "bg-accent font-medium"
                  : "text-muted-foreground hover:bg-accent/60",
              )}
            >
              <span className="truncate">{folder.label}</span>
              {folder.unreadCount != null && folder.unreadCount > 0 ? (
                <span className="rounded-full bg-primary px-1.5 text-[10px] text-primary-foreground">
                  {folder.unreadCount}
                </span>
              ) : null}
            </button>
          ))}
        </nav>
      </div>

      <div className="min-w-0 flex-1 overflow-y-auto bg-card">
        <div className="sticky top-0 z-10 border-b border-border bg-card px-4 py-3" aria-live="polite">
          <p className="text-xs text-muted-foreground">{loading ? "Loading messages…" : `${messages.length} messages`}</p>
          {error ? <p className="mt-1 text-xs text-destructive" role="alert">{error}</p> : null}
        </div>
        {!loading && messages.length === 0 ? (
          <div className="flex h-48 flex-col items-center justify-center px-5 text-center text-sm text-muted-foreground">
            <Mail className="mb-2 size-5" />
            <p className="font-medium text-foreground">This folder is clear</p>
            <p className="mt-1">New synchronized mail will appear here.</p>
          </div>
        ) : (
          <ol>
            {messages.map((message) => (
              <li key={message.id}>
                <button
                  type="button"
                  onClick={() => onSelectMessage(message.id)}
                  aria-current={selectedMessageId === message.id ? "true" : undefined}
                  className={cn(
                    "w-full border-b border-border px-4 py-3 text-left transition-colors hover:bg-accent/50",
                    selectedMessageId === message.id && "bg-info-muted/50",
                  )}
                >
                  <div className="flex items-center gap-2">
                    <span className={cn("min-w-0 flex-1 truncate text-sm", message.unread && "font-semibold")}>
                      {message.sender.name?.trim() || message.sender.address}
                    </span>
                    <time className="shrink-0 text-[11px] text-muted-foreground">{message.receivedAt}</time>
                  </div>
                  <div className="mt-1 flex items-center gap-1.5">
                    {message.starred ? <Star className="size-3 fill-current text-primary" aria-label="Starred" /> : null}
                    <span className={cn("truncate text-[13px]", message.unread ? "font-medium" : "text-foreground/80")}>
                      {message.subject || "(No subject)"}
                    </span>
                    {message.hasAttachments ? (
                      <Paperclip className="size-3 shrink-0 text-muted-foreground" aria-label="Has attachments" />
                    ) : null}
                  </div>
                  <p className="mt-1 line-clamp-2 text-xs leading-relaxed text-muted-foreground">{message.snippet}</p>
                </button>
              </li>
            ))}
          </ol>
        )}
        {hasMore ? (
          <div className="p-3">
            <Button type="button" variant="outline" className="w-full" onClick={onLoadMore} disabled={loading}>
              {loading ? "Loading…" : "Load more messages"}
            </Button>
          </div>
        ) : null}
      </div>
      </div>
    </section>
  )
}
