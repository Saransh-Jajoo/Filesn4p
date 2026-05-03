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

    const contentType = share.contentType || "file";

    // For clipboard-only shares, return the encrypted clipboard text directly
    if (contentType === "clipboard") {
      if (typeof remaining === "number" && remaining <= 0) {
        after(async () => {
          await cleanupShare(share);
        });
      }

      return new Response(JSON.stringify({
        clipboardTextEncrypted: share.clipboardTextEncrypted || "",
        contentType: "clipboard"
      }), {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "Cache-Control": "no-store",
          "X-Clip-Metadata": encodeHeaderJson(clip.metadata),
          "X-Views-Left": String(typeof remaining === "number" ? Math.max(remaining, 0) : 0),
          "X-Content-Type": "clipboard"
        }
      });
    }

    // For file or both: fetch the blob
    const blobResponse = await fetch(share.blobUrl, {
      headers: process.env.BLOB_READ_WRITE_TOKEN
        ? { Authorization: `Bearer ${process.env.BLOB_READ_WRITE_TOKEN}` }
        : undefined,
      cache: "no-store"
    });

    if (!blobResponse.ok || !blobResponse.body) {
      throw new Error("Encrypted payload is no longer available.");
    }

    if (typeof remaining === "number" && remaining <= 0) {
      after(async () => {
        await cleanupShare(share);
      });
    }

    // Build response headers
    const headers: Record<string, string> = {
      "Content-Type": "application/octet-stream",
      "Content-Disposition": `attachment; filename="${clip.id}.bin"`,
      "Cache-Control": "no-store",
      "X-Clip-Metadata": encodeHeaderJson(clip.metadata),
      "X-Views-Left": String(typeof remaining === "number" ? Math.max(remaining, 0) : 0),
      "X-Content-Type": contentType
    };

    // For "both" mode, include clipboard text in header
    if (contentType === "both" && share.clipboardTextEncrypted) {
      headers["X-Clipboard-Text"] = encodeHeaderJson(share.clipboardTextEncrypted);
    }

    return new Response(blobResponse.body, {
      status: 200,
      headers
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "This file is no longer available.";
    const status = error instanceof ApiError ? error.status : 404;
    return Response.json({ error: message }, { status, headers: { "Cache-Control": "no-store" } });
  }
}
