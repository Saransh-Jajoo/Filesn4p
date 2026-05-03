import { jsonError, jsonOk } from "@/lib/http";
import { enforceRateLimit, periodicCleanup } from "@/lib/store";
import { ApiError } from "@/lib/validation";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Periodic cleanup endpoint.
 * Can be called by a cron job (e.g. Vercel Cron) or manually.
 * Sweeps expired shares, orphaned blobs, and stale user records.
 */
export async function GET(request: Request) {
  try {
    await enforceRateLimit(request, "cleanup", 6, 60);
    const cleanupSecret = process.env.CLEANUP_SECRET;
    if (!cleanupSecret && process.env.NODE_ENV === "production") {
      throw new ApiError("Cleanup endpoint is disabled until CLEANUP_SECRET is configured.", 503);
    }
    if (cleanupSecret) {
      const auth = request.headers.get("x-cleanup-secret") || "";
      if (!auth || auth !== cleanupSecret) {
        throw new ApiError("Forbidden: invalid cleanup secret.", 403);
      }
    }
    await periodicCleanup();
    return jsonOk({
      status: "ok"
    });
  } catch (error) {
    return jsonError(error);
  }
}
