import type { AskResult, BootstrapData, ConnectedAccount, FilyApi, JobApplication } from "./types"

const APPLICATIONS: JobApplication[] = [
  {
    id: "demo-application",
    company: "Example Company",
    companyDomain: "example.com",
    position: "Operations Analyst",
    stage: "Applied",
    applicationDate: "Aug 18, 2026",
    nextAction: "Connect the local Fily API to load indexed email evidence.",
    evidence: {
      subject: "Application received",
      from: "careers@example.com",
      receivedAt: "Aug 18, 2026",
      quote: "Your application has been received.",
    },
    thread: [],
  },
]

export class MockFilyApi implements FilyApi {
  async getBootstrap(_applicationLimit: number): Promise<BootstrapData> {
    return {
      folders: [{ id: "job-applications", label: "Job Applications", count: APPLICATIONS.length }],
      accounts: [{ id: "demo", provider: "gmail", email: "demo@example.com" }],
      applications: APPLICATIONS,
    }
  }

  async getAccounts(): Promise<ConnectedAccount[]> {
    return (await this.getBootstrap(5)).accounts
  }

  async getJobApplications(limit: number): Promise<JobApplication[]> {
    return APPLICATIONS.slice(0, limit)
  }

  async getJobApplication(id: string): Promise<JobApplication> {
    const result = APPLICATIONS.find((item) => item.id === id)
    if (!result) throw new Error("Application not found")
    return result
  }

  async askFily(question: string, _limit = 20): Promise<AskResult> {
    return { answer: `Mock Fily would search the local index for: “${question}”` }
  }
}
