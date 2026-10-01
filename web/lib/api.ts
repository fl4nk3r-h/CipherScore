// Typed fetchers for the API (repo.md §8 lib/api.ts).
const BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

async function responseError(res: Response, path: string): Promise<Error> {
  const body = await res.json().catch(() => null);
  const detail = body && typeof body.detail === "string" ? body.detail : res.statusText;
  return new Error(`${res.status} ${path}${detail ? `: ${detail}` : ""}`);
}

export const api = {
  url(path: string): string {
    return `${BASE}${path}`;
  },

  async fetcher<T>(path: string): Promise<T> {
    const res = await fetch(api.url(path));
    if (!res.ok) throw await responseError(res, path);
    return res.json();
  },

  async fetchArray<T>(path: string): Promise<T[]> {
    const data: unknown = await api.fetcher(path);
    if (!Array.isArray(data)) throw new Error(`Invalid response from ${path}: expected an array`);
    return data as T[];
  },

  async post<T>(path: string, body: unknown): Promise<T> {
    const res = await fetch(api.url(path), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw await responseError(res, path);
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
    if (!res.ok) throw await responseError(res, "/captures");
    return res.json();
  },
};
