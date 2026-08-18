import { LocalFilyApi } from "./local"
import { MockFilyApi } from "./mock"
import type { FilyApi } from "./types"

const configuredUrl = process.env.NEXT_PUBLIC_FILY_API_URL?.replace(/\/$/, "")

export const filyApi: FilyApi = configuredUrl
  ? new LocalFilyApi(configuredUrl)
  : new MockFilyApi()

export type {
  ApplicationStage,
  AskResult,
  BootstrapData,
  ConnectedAccount,
  EmailThreadMessage,
  FilyApi,
  JobApplication,
  MailboxFolder,
} from "./types"
