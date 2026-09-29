// Typed fetchers for the API (repo.md §8 lib/api.ts).
const BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

export const api = {
  url(path: string): string {
    return `${BASE}${path}`;
  },

  async fetcher<T>(path: string): Promise<T> {
    const res = await fetch(api.url(path));
    if (!res.ok) throw new Error(`${res.status} ${path}`);
    return res.json();
  },

  async post<T>(path: string, body: unknown): Promise<T> {
    const res = await fetch(api.url(path), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`${res.status} ${path}`);
    return res.json();
  },

  /** True when the resource exists (HEAD) — used to detect un-generated reports. */
  async headExists(path: string): Promise<boolean> {
    try {
      const res = await fetch(api.url(path), { method: "HEAD" });
      return res.ok;
    } catch {
      return false;
    }
  },

  async upload(file: File): Promise<{ capture_id: string }> {
    const form = new FormData();
    form.append("file", file);
    const res = await fetch(api.url("/captures"), { method: "POST", body: form });
    if (!res.ok) throw new Error(`upload failed: ${res.status}`);
    return res.json();
  },
};
