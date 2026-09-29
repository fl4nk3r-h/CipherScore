// shadcn/ui-style Skeleton (repo.md §8 components/ui).
import { cn } from "@/lib/utils";

export function Skeleton({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("animate-pulse rounded-md bg-slate-800", className)} {...props} />;
}