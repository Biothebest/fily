import type {
  AskResult,
  BootstrapData,
  ConnectedAccount,
  FilyApi,
  JobApplication,
  ApplicationStage,
} from "./types"

interface BackendApplication {
  id: string
  company: string
  role: string
  stage: string
  application_date: string
  next_action: string
  evidence: string
  evidence_message_id?: string | null
  account?: string | null
  subject: string
}

interface BackendAccount {
  id: string
  provider: string
  email?: string | null
}

interface BackendBootstrap {
  accounts: BackendAccount[]
  smart_views: Array<{ id: string; label: string; count: number }>
  job_applications: BackendApplication[]
}

const STAGES: Record<ApplicationStage, true> = {
  Applied: true,
  Screening: true,
  Assessment: true,
  Interview: true,
  Offer: true,
  Rejected: true,
  Unknown: true,
}

function application(value: BackendApplication): JobApplication {
  const receivedAt = value.application_date || "Date unavailable"
  const date = receivedAt ? new Date(receivedAt) : null
  const validDate = date && !Number.isNaN(date.getTime())
  const from = value.account || "Indexed email"

  return {
    id: value.id,
    company: value.company,
    companyDomain: "",
    position: value.role,
    stage: STAGES[value.stage as ApplicationStage]
      ? (value.stage as ApplicationStage)
      : "Unknown",
    applicationDate: validDate
      ? new Intl.DateTimeFormat("en-US", { dateStyle: "medium" }).format(date)
      : receivedAt,
    nextAction: value.next_action,
    evidence: {
      subject: value.subject,
      from,
      receivedAt,
      quote: value.evidence,
    },
    thread: [
      {
        id: value.evidence_message_id || value.id,
        from,
        fromName: value.company,
        date: validDate
          ? new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric" }).format(date)
          : receivedAt,
        time: validDate
          ? new Intl.DateTimeFormat("en-US", { hour: "numeric", minute: "2-digit" }).format(date)
          : "",
        preview: value.evidence,
      },
    ],
  }
}

export class LocalFilyApi implements FilyApi {
  constructor(private readonly baseUrl: string) {}

  private async request<T>(path: string, init?: RequestInit): Promise<T> {
    const response = await fetch(`${this.baseUrl}${path}`, {
      ...init,
      headers: { "Content-Type": "application/json", ...init?.headers },
      cache: "no-store",
    })
    const payload = (await response.json()) as T & { error?: string }
    if (!response.ok) throw new Error(payload.error || `Fily API returned ${response.status}`)
    return payload
  }

  async getBootstrap(applicationLimit: number): Promise<BootstrapData> {
    const payload = await this.request<BackendBootstrap>(
      `/v1/bootstrap?application_limit=${encodeURIComponent(applicationLimit)}`,
    )
    return {
      folders: payload.smart_views,
      accounts: payload.accounts.map((item) => ({
        id: item.id,
        provider: item.provider,
        email: item.email || "Local files",
      })),
      applications: payload.job_applications.map(application),
    }
  }

  async getAccounts(): Promise<ConnectedAccount[]> {
    const payload = await this.request<{ accounts: BackendAccount[] }>("/v1/accounts")
    return payload.accounts.map((item) => ({
      id: item.id,
      provider: item.provider,
      email: item.email || "Local files",
    }))
  }

  async getJobApplications(limit: number): Promise<JobApplication[]> {
    const payload = await this.request<{ applications: BackendApplication[] }>(
      `/v1/job-applications?limit=${encodeURIComponent(limit)}`,
    )
    return payload.applications.map(application)
  }

  async getJobApplication(id: string): Promise<JobApplication> {
    const payload = await this.request<{ application: BackendApplication }>(
      `/v1/job-applications/${encodeURIComponent(id)}`,
    )
    return application(payload.application)
  }

  async askFily(question: string, limit = 20): Promise<AskResult> {
    const payload = await this.request<Record<string, unknown>>("/v1/ask", {
      method: "POST",
      body: JSON.stringify({ question, limit }),
    })
    return {
      answer:
        typeof payload.answer === "string"
          ? payload.answer
          : "Fily found matching records but did not return a text answer.",
    }
  }
}
