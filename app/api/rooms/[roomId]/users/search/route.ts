import { jsonError, jsonOk } from "@/lib/http";
import { enforceRateLimit, searchUsers } from "@/lib/store";
import { cleanRoomId } from "@/lib/validation";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request, context: { params: Promise<{ roomId: string }> }) {
  try {
    await enforceRateLimit(request, "search", 120, 60);
    const { roomId: rawRoomId } = await context.params;
    const url = new URL(request.url);
    const roomId = cleanRoomId(rawRoomId);
    const userId = url.searchParams.get("userId") || "";
    const query = (url.searchParams.get("q") || "").trim();
    const users = await searchUsers(roomId, userId, query);

    return jsonOk({
      users: users.map((user) => ({
        id: user.id,
        username: user.username,
        publicKey: user.publicKey,
        fingerprint: user.fingerprint
      }))
    });
  } catch (error) {
    return jsonError(error);
  }
}

