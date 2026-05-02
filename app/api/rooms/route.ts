import { jsonError, jsonOk, readJson } from "@/lib/http";
import { createUser, enforceRateLimit, isDurableStoreConfigured } from "@/lib/store";
import { validateFingerprint, validatePublicKey, validateUsername } from "@/lib/validation";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  try {
    await enforceRateLimit(request, "join", 12, 60);
    const payload = await readJson(request);
    const user = await createUser({
      username: validateUsername(payload.username),
      publicKey: validatePublicKey(payload.publicKey),
      fingerprint: validateFingerprint(payload.fingerprint)
    });

    return jsonOk({
      roomId: user.roomId,
      userId: user.id,
      username: user.username,
      durableStore: isDurableStoreConfigured(),
      blobConfigured: Boolean(process.env.BLOB_READ_WRITE_TOKEN)
    });
  } catch (error) {
    return jsonError(error);
  }
}
