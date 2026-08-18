import { cn } from "@/lib/utils"
import type { ApplicationStage } from "@/lib/fily-api"

const STAGE_STYLES: Record<ApplicationStage, string> = {
  Applied: "bg-info-muted text-info border-info/20",
  Screening: "bg-accent text-accent-foreground border-border",
  Assessment: "bg-accent text-accent-foreground border-border",
  Interview: "bg-accent text-accent-foreground border-border",
  Offer: "bg-accent text-accent-foreground border-border",
  Rejected: "bg-muted text-muted-foreground border-border",
  Unknown: "bg-muted text-muted-foreground border-border",
}

export function StatusBadge({
  stage,
  className,
}: {
  stage: ApplicationStage
  className?: string
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium",
        STAGE_STYLES[stage],
        className,
      )}
    >
      <span className="size-1.5 rounded-full bg-current opacity-70" aria-hidden="true" />
      {stage}
    </span>
  )
}
