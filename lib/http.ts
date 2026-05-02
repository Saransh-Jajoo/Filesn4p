import { NextResponse } from "next/server";
import { ApiError } from "@/lib/validation";

export function jsonOk<T>(body: T, init?: ResponseInit) {
  return NextResponse.json(body, {
    ...init,
    headers: {
      "Cache-Control": "no-store",
      ...(init?.headers || {})
    }
  });
}

export function jsonError(error: unknown) {
  if (error instanceof ApiError) {
    return jsonOk({ error: error.message }, { status: error.status });
  }
  const message = error instanceof Error ? error.message : "Request failed.";
  return jsonOk({ error: message }, { status: 500 });
}

export async function readJson(request: Request) {
  const payload = await request.json().catch(() => null);
  if (!payload || typeof payload !== "object") {
    throw new ApiError("Expected a JSON request body.");
  }
  return payload as Record<string, unknown>;
}

