// Lightweight accessible Tabs (repo.md §8 components/ui). API mirrors the
// shadcn/ui primitives (TabsList / TabsTrigger) without the Radix dependency.
import * as React from "react";
import { cn } from "@/lib/utils";

interface TabsContextValue {
  value: string;
  onValueChange: (value: string) => void;
  baseId: string;
}

const TabsContext = React.createContext<TabsContextValue | null>(null);

export interface TabsProps extends Omit<React.HTMLAttributes<HTMLDivElement>, "onChange"> {
  value: string;
  onValueChange: (value: string) => void;
  children: React.ReactNode;
}

export function Tabs({ value, onValueChange, children, className, ...props }: TabsProps) {
  const baseId = React.useId();
  // If the value no longer matches any trigger, normalise it to "" so screens
  // can opt out of the group entirely (e.g. "all" filters).
  return (
    <TabsContext.Provider value={{ value, onValueChange, baseId }}>
      <div className={className} {...props}>
        {children}
      </div>
    </TabsContext.Provider>
  );
}

export function TabsList({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      role="tablist"
      className={cn("inline-flex items-center gap-1 rounded-md bg-slate-800/70 p-1", className)}
      {...props}
    />
  );
}

export interface TabsTriggerProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  value: string;
}

export function TabsTrigger({ value, className, ...props }: TabsTriggerProps) {
  const ctx = React.useContext(TabsContext);
  const selected = ctx?.value === value;
  return (
    <button
      type="button"
      role="tab"
      id={ctx ? `${ctx.baseId}-tab-${value}` : undefined}
      aria-selected={selected}
      aria-controls={ctx ? `${ctx.baseId}-panel` : undefined}
      tabIndex={selected ? 0 : -1}
      onClick={() => ctx?.onValueChange(value)}
      className={cn(
        "rounded px-3 py-1 text-xs transition-colors focus-visible:outline-none "
          + "focus-visible:ring-2 focus-visible:ring-cyan-500",
        selected ? "bg-cyan-700 text-white" : "text-slate-300 hover:bg-slate-700 hover:text-slate-100",
        className,
      )}
      {...props}
    />
  );
}

export function TabsPanel({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  const ctx = React.useContext(TabsContext);
  return (
    <div role="tabpanel" id={ctx ? `${ctx.baseId}-panel` : undefined} className={className} {...props} />
  );
}