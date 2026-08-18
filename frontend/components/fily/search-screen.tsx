"use client"

import { Search } from "lucide-react"
import type { OpaqueId, SearchHit } from "@/lib/fily-api"

export function SearchScreen({
  query,
  results,
  searching,
  error,
  onQueryChange,
  onSearch,
  onOpenMessage,
}: {
  query: string
  results: SearchHit[]
  searching: boolean
  error: string | null
  onQueryChange: (value: string) => void
  onSearch: () => void
  onOpenMessage: (id: OpaqueId) => void
}) {
  return (
    <section className="h-full flex-1 overflow-y-auto" aria-labelledby="search-heading">
      <div className="mx-auto max-w-4xl px-8 py-8">
        <h1 id="search-heading" className="text-xl font-semibold">Search mail</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Search the encrypted local index. Queries are handled by the trusted core.
        </p>
        <form
          className="mt-5 flex gap-2"
          onSubmit={(event) => {
            event.preventDefault()
            onSearch()
          }}
        >
          <label className="flex min-w-0 flex-1 items-center gap-2 rounded-lg border border-input bg-card px-3 focus-within:ring-2 focus-within:ring-ring/20">
            <Search className="size-4 text-muted-foreground" />
            <span className="sr-only">Search messages</span>
            <input
              type="search"
              value={query}
              maxLength={1000}
              onChange={(event) => onQueryChange(event.target.value)}
              placeholder="Sender, subject, or words in a message"
              className="h-11 min-w-0 flex-1 bg-transparent text-sm outline-none"
            />
          </label>
          <button
            type="submit"
            disabled={!query.trim() || searching}
            className="rounded-lg bg-primary px-5 text-sm font-medium text-primary-foreground disabled:opacity-40"
          >
            {searching ? "Searching…" : "Search"}
          </button>
        </form>

        {error ? <p className="mt-4 rounded-lg border border-destructive/30 p-3 text-sm text-destructive">{error}</p> : null}

        <div className="mt-7">
          {results.length > 0 ? (
            <ol className="divide-y divide-border overflow-hidden rounded-xl border border-border bg-card">
              {results.map((hit) => (
                <li key={hit.message.id}>
                  <button
                    type="button"
                    onClick={() => onOpenMessage(hit.message.id)}
                    className="w-full p-4 text-left transition-colors hover:bg-accent/50"
                  >
                    <div className="flex items-center justify-between gap-4">
                      <span className="truncate text-sm font-medium">
                        {hit.message.sender.name?.trim() || hit.message.sender.address}
                      </span>
                      <time className="shrink-0 text-xs text-muted-foreground">{hit.message.receivedAt}</time>
                    </div>
                    <p className="mt-1 truncate text-sm">{hit.message.subject || "(No subject)"}</p>
                    <p className="mt-1 line-clamp-2 text-xs leading-relaxed text-muted-foreground">
                      {hit.matchedSnippet}
                    </p>
                  </button>
                </li>
              ))}
            </ol>
          ) : query.trim() && !searching && !error ? (
            <p className="py-16 text-center text-sm text-muted-foreground">No matching messages.</p>
          ) : (
            <p className="py-16 text-center text-sm text-muted-foreground">
              Results include sanitized excerpts, never raw message HTML.
            </p>
          )}
        </div>
      </div>
    </section>
  )
}
