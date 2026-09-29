// shadcn/ui-style Badge (repo.md §8 components/ui).
import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium",
  {
    variants: {
      variant: {
        default: "border-transparent bg-cyan-700/80 text-cyan-50",
        secondary: "border-transparent bg-slate-800 text-slate-300",
        outline: "border-slate-700 text-slate-300",
        destructive: "border-transparent bg-red-700/80 text-red-50",
        success: "border-transparent bg-emerald-800/80 text-emerald-50",
        warning: "border-transparent bg-amber-800/80 text-amber-50",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />;
}

export { Badge, badgeVariants };