import { jsonError, jsonOk, readJson } from "@/lib/http";
import { createShare, enforceRateLimit, listInbox } from "@/lib/store";
import {
  ApiError,
  cleanRoomId,
  safeFilename,
  validateBlobPathname,
  validateBlobUrl,
  validateDownloadLimit,
  validateExpirySeconds,
  validateFileSize,
  validateMetadata,
  validateRecipients
} from "@/lib/validation";
import { ENCRYPTION_OVERHEAD_BYTES, MAX_FILE_SIZE_BYTES } from "@/lib/constants";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request, context: { params: Promise<{ roomId: string }> }) {
  try {
    await enforceRateLimit(request, "clips-list", 120, 60);
    const { roomId: rawRoomId } = await context.params;
    const url = new URL(request.url);
    const roomId = cleanRoomId(rawRoomId);
    const userId = url.searchParams.get("userId") || "";
    const clips = await listInbox(roomId, userId);
    return jsonOk({ clips });
  } catch (error) {
    return jsonError(error);
  }
}

export async function POST(request: Request, context: { params: Promise<{ roomId: string }> }) {
  try {
    await enforceRateLimit(request, "clips-create", 30, 60);
    const { roomId: rawRoomId } = await context.params;
    const payload = await readJson(request);
    const roomId = cleanRoomId(rawRoomId);
    const senderId = String(payload.senderId || "");
    const recipientsPayload = validateRecipients(payload.recipients);
    const recipients = recipientsPayload.map((recipient) => {
      if (!recipient || typeof recipient !== "object") throw new ApiError("Recipient metadata is invalid.");
      const item = recipient as Record<string, unknown>;
      return {
        id: String(item.id || ""),
        metadata: validateMetadata(item.metadata)
      };
    });

    const sizeBytes = validateFileSize(payload.sizeBytes);
    const encryptedSizeBytes = Number(payload.encryptedSizeBytes);
    if (
      !Number.isInteger(encryptedSizeBytes) ||
      encryptedSizeBytes < 1 ||
      encryptedSizeBytes > MAX_FILE_SIZE_BYTES + ENCRYPTION_OVERHEAD_BYTES
    ) {
      throw new ApiError("Encrypted payload size is invalid.");
    }

    const share = await createShare({
      roomId,
      senderId,
      recipients,
      originalName: safeFilename(payload.originalName),
      sizeBytes,
      encryptedSizeBytes,
      blobUrl: validateBlobUrl(payload.blobUrl),
      blobDownloadUrl: payload.blobDownloadUrl ? validateBlobUrl(payload.blobDownloadUrl) : undefined,
      blobPathname: validateBlobPathname(payload.blobPathname, roomId),
      expiresInSeconds: validateExpirySeconds(payload.expiresInSeconds),
      downloadLimit: validateDownloadLimit(payload.downloadLimit)
    });

    return jsonOk({
      shareId: share.id,
      clipIds: share.clipIds,
      expiresAt: share.expiresAt,
      recipients: share.recipientIds.length
    });
  } catch (error) {
    return jsonError(error);
  }
}
