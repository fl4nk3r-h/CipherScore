// shadcn/ui-style Button (repo.md §8 components/ui).
import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md "
    + "text-sm font-medium transition-colors focus-visible:outline-none "
    + "focus-visible:ring-2 focus-visible:ring-cyan-500 focus-visible:ring-offset-2 "
    + "focus-visible:ring-offset-slate-950 disabled:pointer-events-none "
    + "disabled:opacity-50",
  {
    variants: {
      variant: {
        default: "bg-cyan-700 text-white hover:bg-cyan-600",
        destructive: "bg-red-700 text-white hover:bg-red-600",
        outline: "border border-slate-700 bg-transparent text-slate-200 hover:bg-slate-800",
        ghost: "text-slate-300 hover:bg-slate-800 hover:text-slate-100",
        secondary: "bg-slate-800 text-slate-100 hover:bg-slate-700",
      },
      size: {
        default: "h-9 px-4 py-2",
        sm: "h-8 rounded-md px-3 text-xs",
        xs: "h-6 rounded px-2 text-xs",
        lg: "h-10 rounded-md px-6",
        icon: "h-9 w-9",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  },
);

// Minimal polymorphic slot: renders a single child (e.g. Next Link) with the
// button's classes and event props merged instead of wrapping it in a <button>.
function Slot({ children, className, ...rest }: {
  children: React.ReactNode;
  className?: string;
} & Record<string, unknown>) {
  const child = React.Children.only(children) as React.ReactElement<Record<string, unknown>>;
  return React.cloneElement(child, {
    className: cn(className, child.props.className),
    ...rest,
  });
}

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, type = "button", asChild, ...props }, ref) => {
    if (asChild) {
      return (
        <Slot className={cn(buttonVariants({ variant, size, className }))} {...props}>
          {props.children}
        </Slot>
      );
    }
    return (
      <button
        ref={ref}
        type={type}
        className={cn(buttonVariants({ variant, size, className }))}
        {...props}
      />
    );
  },
);
Button.displayName = "Button";

export { Button, buttonVariants };