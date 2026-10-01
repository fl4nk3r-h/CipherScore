// Accessible dialog used by the evidence drawer (repo.md §8 components/ui).
//
// A minimal, dependency-free modal: role=dialog + aria-modal, focus managed
// (trapped, returns to trigger on close), Escape to close, background scroll
// locked. Mirrors the shadcn/ui Dialog API surface for the parts this app uses.
import * as React from "react";
import { createPortal } from "react-dom";
import { cn } from "@/lib/utils";

export interface DialogProps {
  open: boolean;
  onClose: () => void;
  labelledBy?: string;
  className?: string;
  children: React.ReactNode;
}

export function Dialog({ open, onClose, labelledBy, className, children }: DialogProps) {
  const panelRef = React.useRef<HTMLDivElement>(null);
  const restoreRef = React.useRef<HTMLElement | null>(null);
  const labelledByRef = React.useRef<string | undefined>(labelledBy);

  React.useEffect(() => {
    if (!open) return;
    const previouslyFocused = document.activeElement as HTMLElement | null;
    restoreRef.current = previouslyFocused;
    labelledByRef.current = labelledBy;

    const panel = panelRef.current;
    const focusables = () =>
      panel ? Array.from(
        panel.querySelectorAll<HTMLElement>(
          'a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])',
        ),
      ) : [];

    if (panel) {
      const first = focusables()[0];
      (first ?? panel).focus();
    }

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        onClose();
        return;
      }
      if (e.key !== "Tab" || !panel) return;
      const list = focusables();
      if (!list.length) {
        e.preventDefault();
        return;
      }
      const first = list[0];
      const last = list[list.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };

    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    document.addEventListener("keydown", onKeyDown, true);
    return () => {
      document.removeEventListener("keydown", onKeyDown, true);
      document.body.style.overflow = prevOverflow;
      restoreRef.current?.focus();
    };
  }, [open, onClose, labelledBy]);

  if (!open) return null;
  return createPortal(
    <div className="fixed inset-0 z-50 overflow-y-auto" role="presentation">
      <div className="fixed inset-0 bg-zinc-950/70" aria-hidden="true" />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={labelledByRef.current}
        className={cn(
          "relative mx-auto my-8 w-[calc(100%-2rem)] max-w-96 rounded-lg border border-zinc-700 "
            + "bg-zinc-900 p-4 text-zinc-100 shadow-xl",
          className,
        )}
      >
        {children}
      </div>
    </div>,
    document.body,
  );
}