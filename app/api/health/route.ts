import { jsonOk } from "@/lib/http";
import { isDurableStoreConfigured } from "@/lib/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  return jsonOk({
    status: "ok",
    durableStore: isDurableStoreConfigured(),
    blobConfigured: Boolean(process.env.BLOB_READ_WRITE_TOKEN)
  });
}
