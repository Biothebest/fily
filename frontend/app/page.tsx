"use client"

import { useEffect, useState } from "react"
import { Workspace } from "@/components/fily/workspace"
import { filyApi, type BootstrapData } from "@/lib/fily-api"

const STARTUP_ATTEMPTS = 20
const STARTUP_DELAY_MS = 250

export default function Page() {
  const [data, setData] = useState<BootstrapData | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false

    async function load() {
      for (let attempt = 0; attempt < STARTUP_ATTEMPTS && !cancelled; attempt += 1) {
        try {
          const bootstrap = await filyApi.getBootstrap(20)
          if (!cancelled) setData(bootstrap)
          return
        } catch (startupError) {
          if (attempt === STARTUP_ATTEMPTS - 1 && !cancelled) {
            setError(
              startupError instanceof Error
                ? startupError.message
                : "The local Fily service did not start.",
            )
            return
          }
          const { promise, resolve } = Promise.withResolvers<void>()
          setTimeout(resolve, STARTUP_DELAY_MS)
          await promise
        }
      }
    }
    load()
    return () => {
      cancelled = true
    }
  }, [])

  if (error) {
    return (
      <main className="flex h-screen items-center justify-center bg-background p-8 text-foreground">
        <div className="max-w-md rounded-xl border border-border bg-card p-6">
          <h1 className="text-lg font-semibold">Fily could not start</h1>
          <p className="mt-2 text-sm text-muted-foreground">{error}</p>
          <p className="mt-3 text-xs text-muted-foreground">
            Close and reopen Fily. Your indexed files have not been changed.
          </p>
        </div>
      </main>
    )
  }

  if (!data) {
    return (
      <main className="flex h-screen items-center justify-center bg-background text-sm text-muted-foreground">
        Starting your private Fily workspace…
      </main>
    )
  }

  return (
    <Workspace
      folders={data.folders}
      accounts={data.accounts}
      applications={data.applications}
    />
  )
}
