"use client"

import { Bot, History, Inbox, Search, Settings, Sparkles } from "lucide-react"
import { cn } from "@/lib/utils"
import type { ConnectedAccount } from "@/lib/fily-api"

export type WorkspaceScreen = "inbox" | "search" | "agent" | "plans" | "audit" | "settings"

const NAVIGATION: Array<{ id: WorkspaceScreen; label: string; icon: typeof Inbox }> = [
  { id: "inbox", label: "Inbox", icon: Inbox },
  { id: "search", label: "Search", icon: Search },
  { id: "agent", label: "Ask & review", icon: Sparkles },
  { id: "plans", label: "Agent plans", icon: Bot },
  { id: "audit", label: "Audit history", icon: History },
]

function FilyLogo() {
  return (
    <div className="flex items-center gap-2 px-2">
      <div className="flex size-7 items-center justify-center rounded-md bg-primary text-primary-foreground">
        <svg viewBox="0 0 24 24" className="size-4" fill="none" aria-hidden="true">
          <path d="M5 4h14v3H9v4h8v3H9v6H5V4Z" fill="currentColor" />
        </svg>
      </div>
      <span className="text-[15px] font-semibold tracking-tight text-sidebar-foreground">Fily</span>
    </div>
  )
}

export function Sidebar({
  accounts,
  screen,
  pendingPlanCount,
  onNavigate,
}: {
  accounts: ConnectedAccount[]
  screen: WorkspaceScreen
  pendingPlanCount: number
  onNavigate: (screen: WorkspaceScreen) => void
}) {
  return (
    <aside className="flex h-full w-60 shrink-0 flex-col border-r border-sidebar-border bg-sidebar">
      <div className="flex h-14 items-center px-3"><FilyLogo /></div>
      <nav className="flex-1 px-2 py-2" aria-label="Fily">
        <ul className="space-y-1">
          {NAVIGATION.map((item) => {
            const Icon = item.icon
            const active = item.id === screen
            return (
              <li key={item.id}>
                <button
                  type="button"
                  onClick={() => onNavigate(item.id)}
                  aria-current={active ? "page" : undefined}
                  className={cn(
                    "flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-sm transition-colors",
                    active
                      ? "bg-sidebar-accent font-medium text-sidebar-accent-foreground"
                      : "text-sidebar-foreground/80 hover:bg-sidebar-accent/60",
                  )}
                >
                  <Icon className={cn("size-4", active ? "text-primary" : "text-muted-foreground")} />
                  <span className="flex-1 text-left">{item.label}</span>
                  {item.id === "plans" && pendingPlanCount > 0 ? (
                    <span className="rounded-full bg-primary px-1.5 py-0.5 text-[10px] text-primary-foreground">
                      {pendingPlanCount}
                    </span>
                  ) : null}
                </button>
              </li>
            )
          })}
        </ul>
      </nav>

      <div className="border-t border-sidebar-border p-2">
        <div className="mb-2 px-2.5 py-2">
          <p className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">Trusted core</p>
          <p className="mt-1 text-xs text-sidebar-foreground/80">
            {accounts.length} connected {accounts.length === 1 ? "account" : "accounts"}
          </p>
        </div>
        <button
          type="button"
          onClick={() => onNavigate("settings")}
          aria-current={screen === "settings" ? "page" : undefined}
          className={cn(
            "flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-sm transition-colors",
            screen === "settings"
              ? "bg-sidebar-accent font-medium text-sidebar-accent-foreground"
              : "text-sidebar-foreground/80 hover:bg-sidebar-accent/60",
          )}
        >
          <Settings className="size-4 text-muted-foreground" /> Account settings
        </button>
      </div>
    </aside>
  )
}
