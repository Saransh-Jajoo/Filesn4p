import {
  CLIP_TYPE,
  CURVE,
  MAX_EXPIRY_SECONDS,
  MAX_FILE_SIZE_BYTES,
  MAX_RECIPIENTS,
  MAX_SAFE_DOWNLOAD_LIMIT,
  MIN_DOWNLOAD_LIMIT,
  MIN_EXPIRY_SECONDS,
  PUBLIC_KEY_TYPE
} from "@/lib/constants";
import type { PublicKeyDoc, RecipientMetadata } from "@/lib/types";

const USERNAME_RE = /^[A-Za-z0-9_. -]{1,32}$/;
const FINGERPRINT_RE = /^[A-F0-9]{4}(?:-[A-F0-9]{4}){3}$/;
const ROOM_RE = /^[A-Z0-9]{6,32}$/;

export class ApiError extends Error {
  status: number;

  constructor(message: string, status = 400) {
    super(message);
    this.status = status;
  }
}

export function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

export function cleanRoomId(roomId: string | undefined) {
  const clean = String(roomId || "").replace(/[^A-Za-z0-9]/g, "").toUpperCase();
  if (!ROOM_RE.test(clean)) throw new ApiError("Invalid lobby identifier.");
  return clean;
}

export function validateUsername(value: unknown) {
  const username = String(value || "").trim();
  if (!USERNAME_RE.test(username)) {
    throw new ApiError("Use 1-32 letters, numbers, spaces, dots, underscores, or dashes.");
  }
  return username;
}

export function validateFingerprint(value: unknown) {
  const fingerprint = String(value || "").trim().toUpperCase();
  if (!FINGERPRINT_RE.test(fingerprint)) throw new ApiError("Invalid key fingerprint.");
  return fingerprint;
}

export function validatePublicKey(value: unknown): PublicKeyDoc {
  if (!value || typeof value !== "object") throw new ApiError("Invalid public key.");
  const key = value as PublicKeyDoc;
  if (
    key.type !== PUBLIC_KEY_TYPE ||
    key.version !== 1 ||
    key.algorithm !== "ECDH" ||
    key.curve !== CURVE ||
    key.publicKey?.format !== "spki" ||
    typeof key.publicKey.data !== "string"
  ) {
    throw new ApiError("Unsupported public key.");
  }
  if (JSON.stringify(key).length > 4096) throw new ApiError("Public key is too large.");
  return key;
}

export function validateMetadata(value: unknown): RecipientMetadata {
  if (!value || typeof value !== "object") throw new ApiError("Clip metadata is invalid.");
  const metadata = value as RecipientMetadata;
  if (
    metadata.type !== CLIP_TYPE ||
    metadata.version !== 1 ||
    metadata.curve !== CURVE ||
    metadata.ephemeralPublicKey?.format !== "spki" ||
    metadata.kdf?.name !== "HKDF" ||
    metadata.kdf?.hash !== "SHA-256" ||
    metadata.wrappedKey?.name !== "AES-GCM" ||
    metadata.cipher?.name !== "AES-GCM"
  ) {
    throw new ApiError("Clip metadata is incomplete.");
  }
  if (JSON.stringify(metadata).length > 10_240) throw new ApiError("Clip metadata is too large.");
  return metadata;
}

export function validateDownloadLimit(value: unknown) {
  const raw = String(value ?? "").trim();
  if (!/^[1-9]\d*$/.test(raw)) throw new ApiError("Download limit must be a positive integer.");
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed < MIN_DOWNLOAD_LIMIT || parsed > MAX_SAFE_DOWNLOAD_LIMIT) {
    throw new ApiError("Download limit is outside the supported integer range.");
  }
  return parsed;
}

export function validateExpirySeconds(value: unknown) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed)) throw new ApiError("Expiry must be a whole number of seconds.");
  if (parsed < MIN_EXPIRY_SECONDS || parsed > MAX_EXPIRY_SECONDS) {
    throw new ApiError("Expiry must be between 1 minute and 3 hours.");
  }
  return parsed;
}

export function validateFileSize(size: unknown) {
  const parsed = Number(size);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > MAX_FILE_SIZE_BYTES) {
    throw new ApiError("File must be between 1 byte and 50 MB.");
  }
  return parsed;
}

export function validateRecipients(value: unknown) {
  if (!Array.isArray(value) || value.length < 1 || value.length > MAX_RECIPIENTS) {
    throw new ApiError(`Select 1-${MAX_RECIPIENTS} recipients.`);
  }
  return value;
}

export function safeFilename(value: unknown) {
  const filename = String(value || "shared-file")
    .replace(/[\\/:*?"<>|]/g, "_")
    .replace(/\s+/g, " ")
    .trim();
  return filename.slice(0, 180) || "shared-file";
}

export function validateBlobUrl(value: unknown) {
  const raw = String(value || "");
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new ApiError("Blob URL is invalid.");
  }

  if (url.protocol !== "https:" || !url.hostname.endsWith(".blob.vercel-storage.com")) {
    throw new ApiError("Blob URL must point to Vercel Blob storage.");
  }

  return url.toString();
}

export function validateBlobPathname(value: unknown, roomId: string) {
  const pathname = String(value || "");
  if (
    pathname.length < 12 ||
    pathname.length > 512 ||
    pathname.includes("..") ||
    pathname.includes("\\") ||
    !pathname.startsWith(`clips/${roomId}/`)
  ) {
    throw new ApiError("Blob pathname is invalid.");
  }
  return pathname;
}
