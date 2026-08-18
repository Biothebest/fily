"use client"

import { useEffect, useState } from "react"
import { Workspace } from "@/components/fily/workspace"
import { filyApi, type BootstrapData } from "@/lib/fily-api"

export default function Page() {
  const [data, setData] = useState<BootstrapData | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    let cancelled = false
    setError(null)
    filyApi
      .getBootstrap(50)
      .then((bootstrap) => {
        if (!cancelled) setData(bootstrap)
      })
      .catch((startupError) => {
        if (!cancelled) {
          setError(
            startupError instanceof Error
              ? startupError.message
              : "The trusted Fily core did not respond.",
          )
        }
      })
    return () => {
      cancelled = true
    }
  }, [attempt])

  if (error) {
    return (
      <main className="flex h-screen items-center justify-center bg-background p-8 text-foreground">
        <div className="max-w-md rounded-xl border border-border bg-card p-6 text-center">
          <h1 className="text-lg font-semibold">Fily could not open your workspace</h1>
          <p className="mt-2 text-sm text-muted-foreground">{error}</p>
          <p className="mt-3 text-xs text-muted-foreground">
            The desktop trusted core is built into Fily. No local web service or sidecar is required.
          </p>
          <button
            type="button"
            onClick={() => setAttempt((value) => value + 1)}
            className="mt-5 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground"
          >
            Try again
          </button>
        </div>
      </main>
    )
  }

  if (!data) {
    return (
      <main className="flex h-screen items-center justify-center bg-background text-sm text-muted-foreground">
        Opening your private Fily workspace…
      </main>
    )
  }

  return <Workspace data={data} />
}
