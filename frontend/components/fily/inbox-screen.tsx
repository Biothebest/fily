"use client"

import { Mail, Paperclip, Star } from "lucide-react"
import { cn } from "@/lib/utils"
import type { MailboxFolder, MessageSummary, OpaqueId } from "@/lib/fily-api"


export function InboxScreen({
  folders,
  messages,
  selectedFolderId,
  selectedMessageId,
  onSelectFolder,
  onSelectMessage,
}: {
  folders: MailboxFolder[]
  messages: MessageSummary[]
  selectedFolderId: OpaqueId | null
  selectedMessageId: OpaqueId | null
  onSelectFolder: (id: OpaqueId | null) => void
  onSelectMessage: (id: OpaqueId) => void
}) {
  const visibleMessages = selectedFolderId
    ? messages.filter((message) => message.folderId === selectedFolderId)
    : messages

  return (
    <section className="flex h-full w-[35rem] shrink-0" aria-label="Inbox">
      <div className="w-52 shrink-0 border-r border-border bg-secondary/20 p-3">
        <h1 className="px-2 pb-2 text-sm font-semibold">Inbox</h1>
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

      <div className="w-[22rem] shrink-0 overflow-y-auto border-r border-border bg-card">
        <div className="sticky top-0 z-10 border-b border-border bg-card px-4 py-3">
          <p className="text-xs text-muted-foreground">{visibleMessages.length} messages</p>
        </div>
        {visibleMessages.length === 0 ? (
          <div className="flex h-48 flex-col items-center justify-center px-5 text-center text-sm text-muted-foreground">
            <Mail className="mb-2 size-5" />
            No messages in this folder.
          </div>
        ) : (
          <ol>
            {visibleMessages.map((message) => (
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
      </div>
    </section>
  )
}
