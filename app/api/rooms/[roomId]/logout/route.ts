import { jsonError, jsonOk, readJson } from "@/lib/http";
import { enforceRateLimit, logoutUser } from "@/lib/store";
import { cleanRoomId } from "@/lib/validation";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request, context: { params: Promise<{ roomId: string }> }) {
  try {
    await enforceRateLimit(request, "logout", 10, 60);
    const { roomId: rawRoomId } = await context.params;
    const payload = await readJson(request);
    const roomId = cleanRoomId(rawRoomId);
    const userId = String(payload.userId || "");
    const purgeData = Boolean(payload.purgeData);

    await logoutUser(roomId, userId, purgeData);

    return jsonOk({
      status: "ok",
      purged: purgeData
    });
  } catch (error) {
    return jsonError(error);
  }
}
