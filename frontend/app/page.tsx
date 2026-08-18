import { filyApi } from "@/lib/fily-api"
import { Workspace } from "@/components/fily/workspace"

export const dynamic = "force-dynamic"

export default async function Page() {
  const { folders, accounts, applications } = await filyApi.getBootstrap(20)

  return <Workspace folders={folders} accounts={accounts} applications={applications} />
}
