import { jsonError, jsonOk, readJson } from "@/lib/http";
import { enforceRateLimit, touchUser } from "@/lib/store";
import { cleanRoomId } from "@/lib/validation";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request, context: { params: Promise<{ roomId: string }> }) {
  try {
    await enforceRateLimit(request, "heartbeat", 80, 60);
    const { roomId: rawRoomId } = await context.params;
    const payload = await readJson(request);
    const roomId = cleanRoomId(rawRoomId);
    const userId = String(payload.userId || "");
    await touchUser(roomId, userId);
    return jsonOk({ status: "ok" });
  } catch (error) {
    return jsonError(error);
  }
}

