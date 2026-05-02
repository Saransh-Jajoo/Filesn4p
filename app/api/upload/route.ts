import { handleUpload, type HandleUploadBody } from "@vercel/blob/client";
import { NextResponse } from "next/server";
import { ENCRYPTION_OVERHEAD_BYTES, MAX_FILE_SIZE_BYTES } from "@/lib/constants";
import { enforceRateLimit, isDurableStoreConfigured, requireActiveUser } from "@/lib/store";
import { ApiError, cleanRoomId } from "@/lib/validation";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  try {
    await enforceRateLimit(request, "blob-upload-token", 30, 60);
    if (!process.env.BLOB_READ_WRITE_TOKEN) {
      throw new ApiError("File uploads are not configured. Add BLOB_READ_WRITE_TOKEN from your Vercel Blob store.");
    }
    if (process.env.VERCEL === "1" && !isDurableStoreConfigured()) {
      throw new ApiError("Vercel metadata storage is not configured. Add UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN.");
    }
    const body = (await request.json()) as HandleUploadBody;

    const response = await handleUpload({
      body,
      request,
      onBeforeGenerateToken: async (_pathname, clientPayload) => {
        const payload = JSON.parse(clientPayload || "{}") as {
          roomId?: string;
          userId?: string;
        };
        const roomId = cleanRoomId(payload.roomId);
        await requireActiveUser(roomId, payload.userId);

        return {
          allowedContentTypes: ["application/octet-stream"],
          maximumSizeInBytes: MAX_FILE_SIZE_BYTES + ENCRYPTION_OVERHEAD_BYTES,
          addRandomSuffix: true,
          tokenPayload: JSON.stringify({
            roomId,
            userId: payload.userId
          })
        };
      },
      onUploadCompleted: async () => undefined
    });

    return NextResponse.json(response, {
      headers: { "Cache-Control": "no-store" }
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Upload authorization failed.";
    const status = error instanceof ApiError ? error.status : 400;
    return NextResponse.json({ error: message }, { status });
  }
}
