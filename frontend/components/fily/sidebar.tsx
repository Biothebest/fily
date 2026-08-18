"use client"

import {
  Inbox,
  Star,
  Briefcase,
  Receipt,
  Plane,
  Settings,
  PenSquare,
  ChevronDown,
} from "lucide-react"
import { cn } from "@/lib/utils"
import type { ConnectedAccount, MailboxFolder } from "@/lib/fily-api"

const FOLDER_ICONS: Record<string, typeof Inbox> = {
  all: Inbox,
  important: Star,
  "job-applications": Briefcase,
  invoices: Receipt,
  travel: Plane,
}

function FilyLogo() {
  return (
    <div className="flex items-center gap-2 px-2">
      <div className="flex size-7 items-center justify-center rounded-md bg-primary text-primary-foreground">
        <svg viewBox="0 0 24 24" className="size-4" fill="none" aria-hidden="true">
          <path
            d="M5 4h14v3H9v4h8v3H9v6H5V4Z"
            fill="currentColor"
          />
        </svg>
      </div>
      <span className="text-[15px] font-semibold tracking-tight text-sidebar-foreground">Fily</span>
    </div>
  )
}

export function Sidebar({
  folders,
  accounts,
  selectedFolderId,
  onSelectFolder,
}: {
  folders: MailboxFolder[]
  accounts: ConnectedAccount[]
  selectedFolderId: string
  onSelectFolder: (id: string) => void
}) {
  return (
    <aside className="flex h-full w-60 shrink-0 flex-col border-r border-sidebar-border bg-sidebar">
      <div className="flex h-14 items-center px-3">
        <FilyLogo />
      </div>

      <div className="px-3 pb-2">
        <button
          type="button"
          className="flex w-full items-center justify-center gap-2 rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground transition-colors hover:brightness-110"
        >
          <PenSquare className="size-4" />
          New message
        </button>
      </div>

      <nav className="flex-1 overflow-y-auto px-2 py-1" aria-label="Mailboxes">
        <ul className="space-y-0.5">
          {folders.map((folder) => {
            const Icon = FOLDER_ICONS[folder.id] ?? Inbox
            const active = folder.id === selectedFolderId
            return (
              <li key={folder.id}>
                <button
                  type="button"
                  onClick={() => onSelectFolder(folder.id)}
                  aria-current={active ? "page" : undefined}
                  className={cn(
                    "group flex w-full items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm transition-colors",
                    active
                      ? "bg-sidebar-accent font-medium text-sidebar-accent-foreground"
                      : "text-sidebar-foreground/80 hover:bg-sidebar-accent/60",
                  )}
                >
                  <Icon className={cn("size-4 shrink-0", active ? "text-primary" : "text-muted-foreground")} />
                  <span className="flex-1 truncate text-left">{folder.label}</span>
                  {folder.count != null && (
                    <span
                      className={cn(
                        "text-xs tabular-nums",
                        active ? "text-sidebar-accent-foreground/70" : "text-muted-foreground/70",
                      )}
                    >
                      {folder.count}
                    </span>
                  )}
                </button>
              </li>
            )
          })}
        </ul>

        <div className="mt-5 px-2.5">
          <div className="flex items-center gap-1 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
            Connected Accounts
            <ChevronDown className="size-3" />
          </div>
          <ul className="mt-2 space-y-0.5">
            {accounts.map((account) => (
              <li key={account.id}>
                <div className="flex items-center gap-2.5 rounded-md px-2.5 py-1.5">
                  <span className="flex size-5 shrink-0 items-center justify-center rounded-full bg-info-muted text-[10px] font-semibold text-info">
                    G
                  </span>
                  <span className="truncate text-xs text-sidebar-foreground/80" title={account.email}>
                    {account.email}
                  </span>
                </div>
              </li>
            ))}
          </ul>
        </div>
      </nav>

      <div className="border-t border-sidebar-border p-2">
        <button
          type="button"
          className="flex w-full items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm text-sidebar-foreground/80 transition-colors hover:bg-sidebar-accent/60"
        >
          <Settings className="size-4 text-muted-foreground" />
          Settings
        </button>
      </div>
    </aside>
  )
}
