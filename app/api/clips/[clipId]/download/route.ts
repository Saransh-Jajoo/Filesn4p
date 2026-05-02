import { after } from "next/server";
import { cleanupShare, claimDownload, enforceRateLimit } from "@/lib/store";
import { ApiError } from "@/lib/validation";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function encodeHeaderJson(value: unknown) {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

export async function GET(request: Request, context: { params: Promise<{ clipId: string }> }) {
  try {
    await enforceRateLimit(request, "download", 60, 60);
    const { clipId } = await context.params;
    const url = new URL(request.url);
    const userId = url.searchParams.get("userId") || "";
    const { clip, share, remaining } = await claimDownload(clipId, userId);

    const blobResponse = await fetch(share.blobUrl, {
      headers: process.env.BLOB_READ_WRITE_TOKEN
        ? { Authorization: `Bearer ${process.env.BLOB_READ_WRITE_TOKEN}` }
        : undefined,
      cache: "no-store"
    });

    if (!blobResponse.ok || !blobResponse.body) {
      throw new Error("Encrypted payload is no longer available.");
    }

    if (remaining <= 0) {
      after(async () => {
        await cleanupShare(share);
      });
    }

    return new Response(blobResponse.body, {
      status: 200,
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Disposition": `attachment; filename="${clip.id}.bin"`,
        "Cache-Control": "no-store",
        "X-Clip-Metadata": encodeHeaderJson(clip.metadata),
        "X-Views-Left": String(Math.max(remaining, 0))
      }
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "This file is no longer available.";
    const status = error instanceof ApiError ? error.status : 404;
    return Response.json({ error: message }, { status, headers: { "Cache-Control": "no-store" } });
  }
}
