// Severity -> Badge mapping shared by Overview/Findings/Lab screens.
import { Badge, type BadgeProps } from "@/components/ui/badge";
import type { Severity } from "@/lib/types";

export function severityBadgeVariant(severity: Severity): NonNullable<BadgeProps["variant"]> {
  switch (severity) {
    case "critical": return "destructive";
    case "high": return "destructive";
    case "medium": return "warning";
    case "low": return "secondary";
    case "info": return "outline";
    default: return "outline";
  }
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <Badge variant={severityBadgeVariant(severity)}>{severity}</Badge>;
}