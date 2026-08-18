"use client"

import { ArrowRight, CalendarDays } from "lucide-react"
import { cn } from "@/lib/utils"
import type { JobApplication } from "@/lib/fily-api"
import { StatusBadge } from "./status-badge"

function CompanyAvatar({ company }: { company: string }) {
  return (
    <span className="flex size-9 shrink-0 items-center justify-center rounded-md border border-border bg-secondary text-sm font-semibold text-foreground/80">
      {company.charAt(0)}
    </span>
  )
}

function ApplicationRow({
  application,
  selected,
  onSelect,
}: {
  application: JobApplication
  selected: boolean
  onSelect: () => void
}) {
  return (
    <li>
      <button
        type="button"
        onClick={onSelect}
        aria-current={selected ? "true" : undefined}
        className={cn(
          "relative flex w-full items-center gap-3.5 px-4 py-3 text-left transition-colors",
          selected ? "bg-info-muted/50" : "hover:bg-accent/50",
        )}
      >
        {selected && <span className="absolute inset-y-2 left-0 w-0.5 rounded-full bg-primary" aria-hidden="true" />}
        <CompanyAvatar company={application.company} />

        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="truncate text-sm font-semibold text-foreground">{application.company}</span>
            <StatusBadge stage={application.stage} />
          </div>
          <p className="mt-0.5 truncate text-[13px] text-muted-foreground">{application.position}</p>
          <div className="mt-1.5 flex items-center gap-1.5 text-xs text-muted-foreground/80">
            <ArrowRight className="size-3 shrink-0" />
            <span className="truncate">{application.nextAction}</span>
          </div>
        </div>

        <div className="flex shrink-0 items-center gap-1 self-start pt-0.5 text-xs text-muted-foreground">
          <CalendarDays className="size-3.5" />
          <span className="tabular-nums">{application.applicationDate}</span>
        </div>
      </button>
    </li>
  )
}

export function ApplicationList({
  applications,
  selectedId,
  onSelect,
  query,
}: {
  applications: JobApplication[]
  selectedId: string | null
  onSelect: (id: string) => void
  query: string
}) {
  return (
    <section className="flex h-full min-w-0 flex-1 flex-col bg-card">
      <header className="flex h-12 items-center justify-between border-b border-border px-4">
        <div className="flex items-center gap-2">
          <h1 className="text-sm font-semibold text-foreground">Job Applications</h1>
          <span className="rounded-full bg-muted px-1.5 py-0.5 text-xs tabular-nums text-muted-foreground">
            {applications.length}
          </span>
        </div>
        <span className="text-xs text-muted-foreground">Sorted by most recent</span>
      </header>

      {applications.length === 0 ? (
        <div className="flex flex-1 flex-col items-center justify-center gap-1 px-6 text-center">
          <p className="text-sm font-medium text-foreground">No applications match your search</p>
          <p className="text-xs text-muted-foreground">
            {query ? `Nothing found for “${query}”.` : "Applications will appear here."}
          </p>
        </div>
      ) : (
        <ul className="flex-1 divide-y divide-border overflow-y-auto">
          {applications.map((application) => (
            <ApplicationRow
              key={application.id}
              application={application}
              selected={application.id === selectedId}
              onSelect={() => onSelect(application.id)}
            />
          ))}
        </ul>
      )}
    </section>
  )
}
