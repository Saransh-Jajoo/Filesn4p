import { jsonError, jsonOk, readJson } from "@/lib/http";
import { createShare, enforceRateLimit, listInbox } from "@/lib/store";
import {
  ApiError,
  cleanRoomId,
  safeFilename,
  validateBlobPathname,
  validateBlobUrl,
  validateClipboardCiphertext,
  validateContentType,
  validateDeletionTrigger,
  validateDownloadLimit,
  validateExpiryMode,
  validateExpirySeconds,
  validateFiles,
  validateMetadata,
  validateRecipients,
  validateTotalSize
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
    const contentType = validateContentType(payload.contentType);
    const deletionTrigger = validateDeletionTrigger(payload.deletionTrigger);
    const expiryMode = validateExpiryMode(payload.expiryMode);

    const recipientsPayload = validateRecipients(payload.recipients);
    const recipients = recipientsPayload.map((recipient) => {
      if (!recipient || typeof recipient !== "object") throw new ApiError("Recipient metadata is invalid.");
      const item = recipient as Record<string, unknown>;
      return {
        id: String(item.id || ""),
        metadata: validateMetadata(item.metadata)
      };
    });

    // Validate files list
    const files = validateFiles(payload.files);

    const hasFiles = files.length > 0;

    // Validate encrypted clipboard text if present
    let clipboardTextEncrypted: string | undefined;
    if (contentType === "clipboard" || contentType === "both") {
      clipboardTextEncrypted = validateClipboardCiphertext(payload.clipboardTextEncrypted);
    }

    // Share composition validation
    if (contentType === "file" && !hasFiles) {
      throw new ApiError("At least one file is required.");
    }
    if (contentType === "clipboard" && hasFiles) {
      throw new ApiError("Clipboard-only shares cannot include files.");
    }
    if (contentType === "both" && !hasFiles) {
      throw new ApiError("At least one file is required for file+clipboard shares.");
    }

    // Policy consistency
    if (deletionTrigger === "time" && expiryMode !== "time") {
      throw new ApiError("Time deletion requires time expiry mode.");
    }
    if ((deletionTrigger === "open" || deletionTrigger === "copy") && expiryMode !== "downloads") {
      throw new ApiError("Open/Copy deletion requires downloads mode.");
    }
    if (deletionTrigger === "download" && expiryMode !== "downloads") {
      throw new ApiError("Download deletion requires downloads mode.");
    }

    // Validate total size (files + clipboard combined)
    const sizeBytes = Number(payload.sizeBytes) || 0;
    validateTotalSize(sizeBytes);

    const encryptedSizeBytes = Number(payload.encryptedSizeBytes);
    if (
      !Number.isInteger(encryptedSizeBytes) ||
      encryptedSizeBytes < 0 ||
      encryptedSizeBytes > MAX_FILE_SIZE_BYTES + ENCRYPTION_OVERHEAD_BYTES
    ) {
      throw new ApiError("Encrypted payload size is invalid.");
    }

    // For clipboard-only shares, blob URL/pathname may be empty
    let blobUrl = "";
    let blobDownloadUrl: string | undefined;
    let blobPathname = "";

    if (contentType === "file" || contentType === "both") {
      blobUrl = validateBlobUrl(payload.blobUrl);
      blobDownloadUrl = payload.blobDownloadUrl ? validateBlobUrl(payload.blobDownloadUrl) : undefined;
      blobPathname = validateBlobPathname(payload.blobPathname, roomId);
    }

    const downloadLimit =
      deletionTrigger === "download" ? validateDownloadLimit(payload.downloadLimit) : deletionTrigger === "time" ? 0 : 1;

    const share = await createShare({
      roomId,
      senderId,
      recipients,
      contentType,
      originalName: safeFilename(payload.originalName),
      files,
      clipboardTextEncrypted,
      sizeBytes,
      encryptedSizeBytes: contentType === "clipboard" ? 0 : encryptedSizeBytes,
      blobUrl,
      blobDownloadUrl,
      blobPathname,
      expiresInSeconds: validateExpirySeconds(payload.expiresInSeconds),
      expiryMode,
      deletionTrigger,
      downloadLimit
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
