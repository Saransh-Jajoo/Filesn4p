import { jsonError, jsonOk } from "@/lib/http";
import { enforceRateLimit, requireActiveUser } from "@/lib/store";
import { cleanRoomId } from "@/lib/validation";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request, context: { params: Promise<{ roomId: string }> }) {
  try {
    await enforceRateLimit(request, "users", 120, 60);
    const { roomId: rawRoomId } = await context.params;
    const url = new URL(request.url);
    const roomId = cleanRoomId(rawRoomId);
    const currentUserId = url.searchParams.get("userId") || "";
    const user = await requireActiveUser(roomId, currentUserId);

    return jsonOk({
      users: [
        {
        id: user.id,
        username: user.username,
        publicKey: user.publicKey,
        fingerprint: user.fingerprint,
        joinedAt: user.joinedAt,
        lastSeen: user.lastSeen,
        isSelf: true
        }
      ]
    });
  } catch (error) {
    return jsonError(error);
  }
}
