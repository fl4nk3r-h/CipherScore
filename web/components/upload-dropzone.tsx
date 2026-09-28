// Drag-and-drop PCAP upload (mvp.md §4 screen 2).
"use client";
import { useRef, useState } from "react";
import { api } from "@/lib/api";

export function UploadDropzone({ onUploaded }: { onUploaded: (captureId: string) => void }) {
  const [dragging, setDragging] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  async function upload(file: File) {
    setBusy(true);
    setError(null);
    try {
      const res = await api.upload(file);   // 500 MB cap enforced server-side
      onUploaded(res.capture_id);
    } catch (e: any) {
      setError(e.message ?? "upload failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div
      onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
        const f = e.dataTransfer.files?.[0];
        if (f) upload(f);
      }}
      onClick={() => inputRef.current?.click()}
      className={`card cursor-pointer text-center transition-colors ${
        dragging ? "border-cyan-500 bg-slate-800/60" : "border-dashed"
      }`}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".pcap,.pcapng"
        className="hidden"
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) upload(f);
        }}
      />
      <p className="text-sm">
        {busy ? "Uploading…" : "Drop a .pcap / .pcapng here, or click to browse"}
      </p>
      <p className="mt-1 text-xs text-slate-500">Max upload size: 500 MB</p>
      {error && <p className="mt-1 text-xs text-red-400">{error}</p>}
    </div>
  );
}
