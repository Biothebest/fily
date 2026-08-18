export type ApplicationStage =
  | "Applied"
  | "Screening"
  | "Assessment"
  | "Interview"
  | "Offer"
  | "Rejected"
  | "Unknown"

export interface EmailThreadMessage {
  id: string
  from: string
  fromName: string
  date: string
  time: string
  preview: string
  unread?: boolean
}

export interface JobApplication {
  id: string
  company: string
  companyDomain: string
  position: string
  stage: ApplicationStage
  applicationDate: string
  nextAction: string
  evidence: {
    subject: string
    from: string
    receivedAt: string
    quote: string
  }
  thread: EmailThreadMessage[]
}

export interface MailboxFolder {
  id: string
  label: string
  count?: number
}

export interface ConnectedAccount {
  id: string
  provider: string
  email: string
}

export interface BootstrapData {
  folders: MailboxFolder[]
  accounts: ConnectedAccount[]
  applications: JobApplication[]
}

export interface AskResult {
  answer: string
}

export interface FilyApi {
  getBootstrap(applicationLimit: number): Promise<BootstrapData>
  getAccounts(): Promise<ConnectedAccount[]>
  getJobApplications(limit: number): Promise<JobApplication[]>
  getJobApplication(id: string): Promise<JobApplication>
  askFily(question: string, limit?: number): Promise<AskResult>
}
