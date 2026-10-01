"use client";

import { useRef, useState } from "react";
import { LoaderCircle, UploadCloud } from "lucide-react";
import { api } from "@/lib/api";

export function UploadDropzone({ onUploaded }: {
  onUploaded: (captureId: string) => void | Promise<void>;
}) {
  const [dragging, setDragging] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  async function upload(file: File) {
    if (busy) return;
    if (!/\.(pcap|pcapng)$/i.test(file.name)) {
      setError("Choose a .pcap or .pcapng capture file.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const result = await api.upload(file);
      await onUploaded(result.capture_id);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Upload failed. Please try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <div
        role="button"
        tabIndex={busy ? -1 : 0}
        aria-label="Upload a PCAP capture"
        aria-busy={busy}
        onKeyDown={(event) => {
          if ((event.key === "Enter" || event.key === " ") && !busy) {
            event.preventDefault();
            inputRef.current?.click();
          }
        }}
        onDragOver={(event) => { event.preventDefault(); if (!busy) setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={(event) => {
          event.preventDefault();
          setDragging(false);
          const file = event.dataTransfer.files?.[0];
          if (file) upload(file);
        }}
        onClick={() => { if (!busy) inputRef.current?.click(); }}
        className={`group flex min-h-56 cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed px-5 py-8 text-center transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500/60 focus-visible:ring-offset-2 focus-visible:ring-offset-zinc-950 ${
          dragging ? "border-cyan-400/70 bg-cyan-500/[0.08]" : "border-white/[0.12] bg-white/[0.015] hover:border-cyan-500/40 hover:bg-white/[0.03]"
        } ${busy ? "cursor-wait opacity-75" : ""}`}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".pcap,.pcapng"
          className="sr-only"
          tabIndex={-1}
          onClick={(event) => event.stopPropagation()}
          onChange={(event) => {
            const file = event.target.files?.[0];
            if (file) upload(file);
            event.currentTarget.value = "";
          }}
        />
        <span className="flex h-12 w-12 items-center justify-center rounded-xl bg-cyan-500/10 text-cyan-300 ring-1 ring-inset ring-cyan-500/20">
          {busy ? <LoaderCircle className="h-6 w-6 animate-spin" /> : <UploadCloud className="h-6 w-6" />}
        </span>
        <span className="mt-4 text-sm font-semibold text-zinc-100">
          {busy ? "Uploading capture…" : dragging ? "Drop your capture here" : "Drop a capture here or browse files"}
        </span>
        <span className="mt-1 max-w-sm text-xs leading-relaxed text-zinc-500">
          {busy ? "Analysis starts as soon as the upload finishes." : "PCAP and PCAPNG files up to 500 MB"}
        </span>
        {!busy && <span className="mt-4 rounded-md border border-white/[0.12] bg-white/[0.05] px-3 py-1.5 text-xs font-medium text-zinc-200 group-hover:border-cyan-500/30">Choose file</span>}
      </div>
      {error && <p role="alert" className="mt-2 text-xs text-red-300">{error}</p>}
    </div>
  );
}
