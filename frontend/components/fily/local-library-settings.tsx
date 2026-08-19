"use client"

import { useEffect, useState } from "react"
import { FolderOpen, RefreshCw, ShieldCheck, Trash2 } from "lucide-react"
import { filyApi, type FolderGrant, type OpaqueId } from "@/lib/fily-api"

export function LocalLibrarySettings() {
  const [grants, setGrants] = useState<FolderGrant[]>([])
  const [busy, setBusy] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    filyApi.listFolderGrants()
      .then((items) => { if (active) setGrants(items) })
      .catch((cause) => { if (active) setError(cause instanceof Error ? cause.message : "Fily could not load approved folders.") })
    return () => { active = false }
  }, [])

  async function addFolder() {
    setBusy("add")
    setError(null)
    setNotice(null)
    try {
      const grant = await filyApi.pickFolderGrant()
      if (!grant) return
      const records = await filyApi.rescanFolderGrant(grant.id)
      setGrants((current) => [...current.filter((item) => item.id !== grant.id), grant])
      setNotice(`Indexed ${records.length} files from the approved folder.`)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Fily could not approve that folder.")
    } finally {
      setBusy(null)
    }
  }

  async function rescan(id: OpaqueId) {
    setBusy(id)
    setError(null)
    try {
      const records = await filyApi.rescanFolderGrant(id)
      setNotice(`Indexed ${records.length} files.`)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Fily could not rescan that folder.")
    } finally {
      setBusy(null)
    }
  }

  async function revoke(id: OpaqueId) {
    setBusy(id)
    setError(null)
    try {
      await filyApi.revokeFolderGrant(id)
      setGrants((current) => current.filter((item) => item.id !== id))
      setNotice("Folder access revoked. Existing indexed metadata remains encrypted locally.")
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Fily could not revoke that folder.")
    } finally {
      setBusy(null)
    }
  }

  return (
    <section className="mt-6 rounded-xl border border-border bg-card p-5" aria-labelledby="local-library-heading">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2"><ShieldCheck className="size-4 text-primary" /><h2 id="local-library-heading" className="text-sm font-semibold">Local file library</h2></div>
          <p className="mt-1 text-xs text-muted-foreground">Fily watches only folders you explicitly approve. Moves, renames, archives, and trash actions require a review plan.</p>
        </div>
        <button type="button" disabled={busy !== null} onClick={() => void addFolder()} className="flex shrink-0 items-center gap-1.5 rounded-md bg-primary px-3 py-2 text-xs font-semibold text-primary-foreground disabled:opacity-40"><FolderOpen className="size-3.5" />{busy === "add" ? "Choosing…" : "Approve folder"}</button>
      </div>
      {notice ? <p className="mt-3 rounded-md bg-info-muted px-3 py-2 text-xs" role="status">{notice}</p> : null}
      {error ? <p className="mt-3 text-xs text-destructive" role="alert">{error}</p> : null}
      {grants.length === 0 ? <p className="mt-4 text-xs text-muted-foreground">No local folders approved.</p> : <ul className="mt-4 divide-y border-y">{grants.map((grant) => <li key={grant.id} className="flex items-center justify-between gap-3 py-3"><span className="min-w-0 truncate text-xs" title={grant.canonicalPath}>{grant.canonicalPath}</span><span className="flex shrink-0 gap-2"><button type="button" disabled={busy !== null} onClick={() => void rescan(grant.id)} className="rounded-md border p-2 hover:bg-accent disabled:opacity-40" aria-label={`Rescan ${grant.canonicalPath}`}><RefreshCw className="size-3.5" /></button><button type="button" disabled={busy !== null} onClick={() => void revoke(grant.id)} className="rounded-md border border-destructive/30 p-2 text-destructive hover:bg-destructive/5 disabled:opacity-40" aria-label={`Revoke ${grant.canonicalPath}`}><Trash2 className="size-3.5" /></button></span></li>)}</ul>}
    </section>
  )
}
