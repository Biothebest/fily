"use client"

import { Search, Sparkles } from "lucide-react"
import { cn } from "@/lib/utils"

export function AskBar({
  value,
  onChange,
  onSubmit,
}: {
  value: string
  onChange: (value: string) => void
  onSubmit: (value: string) => void
}) {
  return (
    <div className="flex h-14 items-center gap-3 border-b border-border bg-card px-4">
      <form
        className="group flex flex-1 items-center gap-2.5 rounded-lg border border-border bg-background px-3 py-2 transition-colors focus-within:border-primary/50 focus-within:bg-card focus-within:ring-2 focus-within:ring-ring/15"
        onSubmit={(e) => {
          e.preventDefault()
          onSubmit(value)
        }}
      >
        <Sparkles className="size-4 shrink-0 text-primary" />
        <input
          type="text"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder="Ask Fily anything about your email…"
          className="min-w-0 flex-1 bg-transparent text-sm text-foreground placeholder:text-muted-foreground focus:outline-none"
          aria-label="Ask Fily anything about your email"
        />
        <kbd
          className={cn(
            "hidden shrink-0 rounded border border-border bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground sm:inline-block",
          )}
        >
          ⌘K
        </kbd>
      </form>

      <button
        type="button"
        className="flex size-9 shrink-0 items-center justify-center rounded-lg border border-border bg-background text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
        aria-label="Search mail"
      >
        <Search className="size-4" />
      </button>
    </div>
  )
}
