"use client";

import { upload } from "@vercel/blob/client";
import { AnimatePresence, motion } from "framer-motion";
import {
  AlertCircle,
  ArrowLeft,
  Check,
  Clipboard,
  Clock,
  Copy,
  Download,
  Eye,
  FileText,
  Inbox,
  LogOut,
  Moon,
  Search,
  Send,
  ShieldCheck,
  Sun,
  UploadCloud,
  Users,
  X
} from "lucide-react";
import Image from "next/image";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  CLIP_TYPE,
  CURVE,
  MAX_CLIPBOARD_TEXT_BYTES,
  MAX_DOWNLOAD_LIMIT,
  MAX_EXPIRY_SECONDS,
  MAX_FILE_SIZE_BYTES,
  PUBLIC_KEY_TYPE
} from "@/lib/constants";
import type { ContentType, DeletionTrigger } from "@/lib/constants";
import type { InboxClip, PublicKeyDoc, RecipientMetadata } from "@/lib/types";

type Theme = "light" | "dark";
type Tab = "send" | "inbox";
type Step = "file" | "recipients" | "sent";
type StatusKind = "error" | "success" | undefined;

type Identity = {
  keyPair: CryptoKeyPair;
  publicKey: PublicKeyDoc;
  fingerprint: string;
};

type User = {
  id: string;
  username: string;
  publicKey: PublicKeyDoc;
  fingerprint: string;
  isSelf?: boolean;
};

type Session = {
  roomId: string;
  userId: string;
  username: string;
  durableStore: boolean;
  blobConfigured: boolean;
};

type ExpiryMode = "downloads" | "time";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const WRAP_INFO = encoder.encode("filesn4p-live-clipboard-v1");
const CURVE_BITS = 256;

function subtleCrypto() {
  if (!window.crypto?.subtle) throw new Error("Web Crypto requires localhost or HTTPS.");
  return window.crypto.subtle;
}

function randomBytes(length: number) {
  const bytes = new Uint8Array(length);
  window.crypto.getRandomValues(bytes);
  return bytes;
}

function toBase64(buffer: ArrayBuffer | Uint8Array) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

function fromBase64(value: string) {
  const binary = atob(String(value || "").replace(/\s/g, ""));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function exactArrayBuffer(bytes: Uint8Array) {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function decodeHeaderJson<T>(value: string | null): T {
  if (!value) throw new Error("Missing encrypted file metadata.");
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  return JSON.parse(decoder.decode(fromBase64(padded))) as T;
}

function sanitizeName(name: string) {
  return String(name || "shared-file")
    .replace(/[\\/:*?"<>|]/g, "_")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 180) || "shared-file";
}

function formatBytes(size: number) {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / (1024 * 1024)).toFixed(1)} MB`;
}

function formatTimeLeft(expiresAt: number) {
  const remaining = Math.max(0, expiresAt - Math.floor(Date.now() / 1000));
  if (remaining < 60) return `${remaining}s`;
  if (remaining < 3600) return `${Math.ceil(remaining / 60)}m`;
  const hours = Math.floor(remaining / 3600);
  const minutes = Math.ceil((remaining % 3600) / 60);
  return minutes ? `${hours}h ${minutes}m` : `${hours}h`;
}

async function apiJson<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    ...init,
    headers: {
      ...(init?.body instanceof FormData ? {} : { "Content-Type": "application/json" }),
      ...(init?.headers || {})
    },
    cache: "no-store"
  });

  if (!response.ok) {
    const data = await response.json().catch(() => null);
    throw new Error(data?.error || response.statusText || "Request failed.");
  }

  return response.json() as Promise<T>;
}

async function generateIdentity(): Promise<Identity> {
  const keyPair = await subtleCrypto().generateKey({ name: "ECDH", namedCurve: CURVE }, true, ["deriveBits"]);
  const spki = await subtleCrypto().exportKey("spki", keyPair.publicKey);
  const hash = new Uint8Array(await subtleCrypto().digest("SHA-256", spki));
  const fingerprint = Array.from(hash.slice(0, 8), (byte) => byte.toString(16).padStart(2, "0").toUpperCase())
    .join("")
    .match(/.{1,4}/g)!
    .join("-");

  return {
    keyPair,
    fingerprint,
    publicKey: {
      type: PUBLIC_KEY_TYPE,
      version: 1,
      algorithm: "ECDH",
      curve: CURVE,
      publicKey: { format: "spki", data: toBase64(spki) }
    }
  };
}

async function importPublicKey(doc: PublicKeyDoc) {
  if (doc.type !== PUBLIC_KEY_TYPE || doc.curve !== CURVE) throw new Error("Recipient key is not supported.");
  return subtleCrypto().importKey("spki", fromBase64(doc.publicKey.data), { name: "ECDH", namedCurve: CURVE }, false, []);
}

async function deriveWrapKey(privateKey: CryptoKey, publicKey: CryptoKey, salt: Uint8Array, usages: KeyUsage[]) {
  const shared = await subtleCrypto().deriveBits({ name: "ECDH", public: publicKey }, privateKey, CURVE_BITS);
  const material = await subtleCrypto().importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  return subtleCrypto().deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: exactArrayBuffer(salt), info: exactArrayBuffer(WRAP_INFO) },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    usages
  );
}

async function encryptForShare(files: File[], clipboardText: string | undefined, recipients: User[], session: Session, identity: Identity) {
  const fileKey = await subtleCrypto().generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const fileNonce = randomBytes(12);

  const fileInfos = files.map((f) => ({ name: sanitizeName(f.name), sizeBytes: f.size }));
  let encryptedBlob: Blob;

  if (files.length > 0) {
    // Build plaintext: [4-byte manifest length][manifest JSON][file1 bytes][file2 bytes]...
    const manifest = JSON.stringify({ version: 1, files: fileInfos });
    const manifestBytes = encoder.encode(manifest);
    const prefix = new Uint8Array(4);
    new DataView(prefix.buffer).setUint32(0, manifestBytes.length, false);

    const fileBuffers = await Promise.all(files.map((f) => f.arrayBuffer()));
    const totalSize = prefix.length + manifestBytes.length + fileBuffers.reduce((sum, buf) => sum + buf.byteLength, 0);
    const plaintext = new Uint8Array(totalSize);
    let offset = 0;
    plaintext.set(prefix, offset); offset += prefix.length;
    plaintext.set(manifestBytes, offset); offset += manifestBytes.length;
    for (const buf of fileBuffers) {
      plaintext.set(new Uint8Array(buf), offset); offset += buf.byteLength;
    }

    const ciphertext = await subtleCrypto().encrypt({ name: "AES-GCM", iv: fileNonce }, fileKey, exactArrayBuffer(plaintext));
    encryptedBlob = new Blob([ciphertext], { type: "application/octet-stream" });
  } else {
    encryptedBlob = new Blob([], { type: "application/octet-stream" });
  }

  const rawFileKey = await subtleCrypto().exportKey("raw", fileKey);

  // Encrypt clipboard text with same key, separate nonce
  let clipboardCipherNonce: Uint8Array | undefined;
  let clipboardTextEncrypted: string | undefined;
  if (clipboardText) {
    clipboardCipherNonce = randomBytes(12);
    const clipPlaintext = encoder.encode(clipboardText);
    const clipCiphertext = await subtleCrypto().encrypt({ name: "AES-GCM", iv: exactArrayBuffer(clipboardCipherNonce) }, fileKey, exactArrayBuffer(clipPlaintext));
    clipboardTextEncrypted = toBase64(clipCiphertext);
  }

  const recipientMetadata = await Promise.all(
    recipients.map(async (recipient) => {
      const recipientPublicKey = await importPublicKey(recipient.publicKey);
      const ephemeral = await subtleCrypto().generateKey({ name: "ECDH", namedCurve: CURVE }, true, ["deriveBits"]);
      const wrapSalt = randomBytes(16);
      const wrapNonce = randomBytes(12);
      const wrapKey = await deriveWrapKey(ephemeral.privateKey, recipientPublicKey, wrapSalt, ["encrypt"]);
      const wrappedKey = await subtleCrypto().encrypt({ name: "AES-GCM", iv: wrapNonce }, wrapKey, rawFileKey);
      const ephemeralPublic = await subtleCrypto().exportKey("spki", ephemeral.publicKey);

      const metadata: RecipientMetadata = {
        type: CLIP_TYPE,
        version: 1,
        algorithm: "ECDH-HKDF-SHA256-AES-256-GCM",
        curve: CURVE,
        filename: fileInfos.length === 1 ? fileInfos[0].name : "shared-files.bin",
        files: fileInfos.length > 1 ? fileInfos : undefined,
        hasClipboard: !!clipboardText,
        sender: { username: session.username, fingerprint: identity.fingerprint },
        recipient: { username: recipient.username, fingerprint: recipient.fingerprint },
        ephemeralPublicKey: { format: "spki", data: toBase64(ephemeralPublic) },
        kdf: { name: "HKDF", hash: "SHA-256", salt: toBase64(wrapSalt), info: toBase64(WRAP_INFO) },
        wrappedKey: { name: "AES-GCM", nonce: toBase64(wrapNonce), data: toBase64(wrappedKey) },
        cipher: { name: "AES-GCM", nonce: toBase64(fileNonce) },
        clipboardCipher: clipboardCipherNonce ? { name: "AES-GCM", nonce: toBase64(clipboardCipherNonce) } : undefined
      };

      return { id: recipient.id, metadata };
    })
  );

  return {
    encryptedBlob,
    recipients: recipientMetadata,
    clipboardTextEncrypted,
    fileInfos
  };
}

type DecryptedPayload = {
  files: Array<{ name: string; data: ArrayBuffer }>;
  clipboardText?: string;
};

async function decryptClip(metadata: RecipientMetadata, encrypted: ArrayBuffer, identity: Identity, clipboardEncrypted?: string): Promise<DecryptedPayload> {
  if (metadata.type !== CLIP_TYPE || metadata.curve !== CURVE) throw new Error("Encrypted file metadata is invalid.");
  const senderPublic = await subtleCrypto().importKey(
    "spki",
    fromBase64(metadata.ephemeralPublicKey.data),
    { name: "ECDH", namedCurve: CURVE },
    false,
    []
  );
  const wrapKey = await deriveWrapKey(identity.keyPair.privateKey, senderPublic, fromBase64(metadata.kdf.salt), ["decrypt"]);
  const rawFileKey = await subtleCrypto().decrypt(
    { name: "AES-GCM", iv: fromBase64(metadata.wrappedKey.nonce) },
    wrapKey,
    fromBase64(metadata.wrappedKey.data)
  );
  const fileKey = await subtleCrypto().importKey("raw", rawFileKey, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);

  // If no file payload (clipboard-only), skip file decryption
  if (!encrypted.byteLength) {
    let clipboardText: string | undefined;
    if (metadata.hasClipboard && metadata.clipboardCipher && clipboardEncrypted) {
      const clipCiphertext = fromBase64(clipboardEncrypted);
      const clipPlaintext = await subtleCrypto().decrypt({ name: "AES-GCM", iv: fromBase64(metadata.clipboardCipher.nonce) }, fileKey, clipCiphertext);
      clipboardText = decoder.decode(clipPlaintext);
    }
    return { files: [], clipboardText };
  }

  const plaintext = await subtleCrypto().decrypt({ name: "AES-GCM", iv: fromBase64(metadata.cipher.nonce) }, fileKey, encrypted);
  const bytes = new Uint8Array(plaintext);

  // Parse manifest: [4-byte length][manifest JSON][file data...]
  const manifestLen = new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, false);
  const manifestJson = decoder.decode(bytes.slice(4, 4 + manifestLen));
  const manifest = JSON.parse(manifestJson) as { version: number; files: Array<{ name: string; sizeBytes: number }> };

  let fileOffset = 4 + manifestLen;
  const files = manifest.files.map((f) => {
    const data = bytes.slice(fileOffset, fileOffset + f.sizeBytes).buffer;
    fileOffset += f.sizeBytes;
    return { name: f.name, data };
  });

  // Decrypt clipboard text if present
  let clipboardText: string | undefined;
  if (metadata.hasClipboard && metadata.clipboardCipher && clipboardEncrypted) {
    const clipCiphertext = fromBase64(clipboardEncrypted);
    const clipPlaintext = await subtleCrypto().decrypt({ name: "AES-GCM", iv: fromBase64(metadata.clipboardCipher.nonce) }, fileKey, clipCiphertext);
    clipboardText = decoder.decode(clipPlaintext);
  }

  return { files, clipboardText };
}

function downloadBuffer(buffer: ArrayBuffer, filename: string) {
  const blob = new Blob([buffer], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = sanitizeName(filename);
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1200);
}

function errorMessage(error: unknown) {
  const message = error instanceof Error ? error.message : "Request failed.";
  if (message.toLowerCase().includes("failed to retrieve the client token")) {
    return "Upload token could not be created. In Vercel, connect a Blob store, set BLOB_READ_WRITE_TOKEN, set Redis env variables, then redeploy.";
  }
  if (error instanceof DOMException && error.name === "AbortError") {
    return "Upload timed out. Check your internet connection and try again.";
  }
  if (message.toLowerCase().includes("request was aborted")) {
    return "Upload timed out. Check your internet connection and try again.";
  }
  return message;
}

export default function SecureShareApp() {
  const [theme, setTheme] = useState<Theme>("dark");
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [username, setUsername] = useState("");
  const [status, setStatus] = useState<{ text: string; kind?: StatusKind }>({ text: "" });
  const [tab, setTab] = useState<Tab>("send");
  const [step, setStep] = useState<Step>("file");
  const [dragging, setDragging] = useState(false);
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [clipboardText, setClipboardText] = useState("");
  const [contentType, setContentType] = useState<ContentType>("file");
  const [deletionTrigger, setDeletionTrigger] = useState<DeletionTrigger>("download");
  const [expiryMode, setExpiryMode] = useState<ExpiryMode>("downloads");
  const [downloadLimit, setDownloadLimit] = useState("1");
  const [expirySeconds, setExpirySeconds] = useState("3600");
  const [searchQuery, setSearchQuery] = useState("");
  const [hasSearched, setHasSearched] = useState(false);
  const [searchResults, setSearchResults] = useState<User[]>([]);
  const [selectedRecipients, setSelectedRecipients] = useState<User[]>([]);
  const [inbox, setInbox] = useState<InboxClip[]>([]);
  const [busy, setBusy] = useState(false);
  const [alertFile, setAlertFile] = useState<{ name: string; size: number } | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [uploadedBlob, setUploadedBlob] = useState<{ url: string; downloadUrl?: string; pathname: string } | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [preparedPayload, setPreparedPayload] = useState<
    | {
        encryptedBlob: Blob;
        rawFileKeyBase64: string;
        fileInfos: Array<{ name: string; sizeBytes: number }>;
        fileNonceBase64: string;
        clipboardTextEncrypted?: string;
      }
    | null
  >(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const logo = theme === "light" ? "/logo-light.svg" : "/logo-dark.svg";
  const selectedIds = useMemo(() => new Set(selectedRecipients.map((recipient) => recipient.id)), [selectedRecipients]);
  const totalFileSize = useMemo(() => selectedFiles.reduce((sum, f) => sum + f.size, 0), [selectedFiles]);

  useEffect(() => {
    const saved = window.localStorage.getItem("filesn4p-theme") as Theme | null;
    const preferred: Theme = saved || (window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
    setTheme(preferred);
    document.documentElement.dataset.theme = preferred;

    const media = window.matchMedia("(prefers-color-scheme: light)");
    const onChange = (event: MediaQueryListEvent) => {
      if (window.localStorage.getItem("filesn4p-theme")) return;
      const next = event.matches ? "light" : "dark";
      setTheme(next);
      document.documentElement.dataset.theme = next;
    };
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, []);

  const toggleTheme = () => {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    document.documentElement.dataset.theme = next;
    window.localStorage.setItem("filesn4p-theme", next);
  };

  const refreshInbox = useCallback(async () => {
    if (!session) return;
    const data = await apiJson<{ clips: InboxClip[] }>(`/api/rooms/${session.roomId}/clips?userId=${encodeURIComponent(session.userId)}`);
    setInbox(data.clips);
  }, [session]);

  useEffect(() => {
    if (!session) return undefined;
    let cancelled = false;

    const heartbeat = async () => {
      await apiJson(`/api/rooms/${session.roomId}/heartbeat`, {
        method: "POST",
        body: JSON.stringify({ userId: session.userId })
      });
    };

    heartbeat().catch(() => undefined);
    refreshInbox().catch(() => undefined);

    const heartbeatId = window.setInterval(() => {
      if (!cancelled) heartbeat().catch(() => setStatus({ text: "Lobby session expired. Join again.", kind: "error" }));
    }, 15_000);
    const inboxId = window.setInterval(() => {
      if (!cancelled) refreshInbox().catch(() => undefined);
    }, 5_000);

    return () => {
      cancelled = true;
      window.clearInterval(heartbeatId);
      window.clearInterval(inboxId);
    };
  }, [refreshInbox, session]);

  const login = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setBusy(true);
    setStatus({ text: "Creating browser keys..." });
    try {
      const nextIdentity = await generateIdentity();
      const data = await apiJson<Session>("/api/rooms", {
        method: "POST",
        body: JSON.stringify({
          username,
          publicKey: nextIdentity.publicKey,
          fingerprint: nextIdentity.fingerprint
        })
      });
      setIdentity(nextIdentity);
      setSession(data);
      setStatus({
        text: !data.blobConfigured
          ? "Uploads need BLOB_READ_WRITE_TOKEN from Vercel Blob."
          : data.durableStore
            ? ""
            : "Local memory mode is active. Configure Redis for Vercel production.",
        kind: !data.blobConfigured || !data.durableStore ? "error" : undefined
      });
    } catch (error) {
      setStatus({ text: errorMessage(error), kind: "error" });
    } finally {
      setBusy(false);
    }
  };

  const logout = async () => {
    if (session) {
      try {
        await apiJson(`/api/rooms/${session.roomId}/logout`, {
          method: "POST",
          body: JSON.stringify({ userId: session.userId, purgeData: true })
        });
      } catch {
        // Best-effort — continue clearing local state
      }
    }
    setSession(null);
    setIdentity(null);
    setSelectedFiles([]);
    setClipboardText("");
    setContentType("file");
    setDeletionTrigger("download");
    setSelectedRecipients([]);
    setSearchResults([]);
    setInbox([]);
    setStep("file");
    setTab("send");
    setStatus({ text: "" });
  };

  const addFiles = (newFiles: FileList | File[]) => {
    const additions = Array.from(newFiles);
    const updated = [...selectedFiles];
    for (const file of additions) {
      if (file.size > MAX_FILE_SIZE_BYTES) {
        setAlertFile({ name: file.name, size: file.size });
        continue;
      }
      const newSize = updated.reduce((sum, f) => sum + f.size, 0) + file.size;
      if (newSize > MAX_FILE_SIZE_BYTES) {
        setAlertFile({ name: file.name, size: newSize });
        continue;
      }
      updated.push(file);
    }
    setSelectedFiles(updated);
    // If running in a session with blob configured, prepare and upload immediately
    if (session && session.blobConfigured) {
      // Upload the current selected files as a single encrypted payload
      uploadSelectedFiles(updated).catch((err) => setStatus({ text: errorMessage(err), kind: "error" }));
    }
  };

  const removeFile = (index: number) => {
    setSelectedFiles((prev) => prev.filter((_, i) => i !== index));
  };

  // Prepare encrypted payload (files + optional clipboard) without recipient wrapping,
  // export the raw file key, then upload to Vercel Blob immediately.
  const uploadSelectedFiles = async (files: File[]) => {
    if (!session) return;
    if (!files.length) return;
    setIsUploading(true);
    const startTime = Date.now();
    
    try {
      setStatus({ text: "Preparing encrypted payload..." });

      // Build manifest and plaintext as in encryptForShare
      const fileInfos = files.map((f) => ({ name: sanitizeName(f.name), sizeBytes: f.size }));
      const manifest = JSON.stringify({ version: 1, files: fileInfos });
      const manifestBytes = encoder.encode(manifest);
      const prefix = new Uint8Array(4);
      new DataView(prefix.buffer).setUint32(0, manifestBytes.length, false);

      const fileBuffers = await Promise.all(files.map((f) => f.arrayBuffer()));
      const totalSize = prefix.length + manifestBytes.length + fileBuffers.reduce((sum, buf) => sum + buf.byteLength, 0);
      const plaintext = new Uint8Array(totalSize);
      let offset = 0;
      plaintext.set(prefix, offset);
      offset += prefix.length;
      plaintext.set(manifestBytes, offset);
      offset += manifestBytes.length;
      for (const buf of fileBuffers) {
        plaintext.set(new Uint8Array(buf), offset);
        offset += buf.byteLength;
      }

      const fileKey = await subtleCrypto().generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
      const fileNonce = randomBytes(12);
      const ciphertext = await subtleCrypto().encrypt({ name: "AES-GCM", iv: fileNonce }, fileKey, exactArrayBuffer(plaintext));
      const encryptedBlobLocal = new Blob([ciphertext], { type: "application/octet-stream" });
      const rawFileKey = await subtleCrypto().exportKey("raw", fileKey);
      const rawKeyBase64 = toBase64(rawFileKey);
      const fileNonceBase64 = toBase64(fileNonce);

      setStatus({ text: `Uploading encrypted payload (${formatBytes(encryptedBlobLocal.size)})...` });

      const pathname = `clips/${session.roomId}/${crypto.randomUUID()}-${sanitizeName(files[0].name)}.bin`;

      const uploadController = new AbortController();
      
      // Use a longer timeout (90 seconds) and add elapsed time tracking
      const uploadPromise = upload(pathname, encryptedBlobLocal, {
        access: "private",
        handleUploadUrl: "/api/upload",
        clientPayload: JSON.stringify({ roomId: session.roomId, userId: session.userId }),
        abortSignal: uploadController.signal
      });

      // Set up timeout with abort
      const uploadTimeoutId = window.setTimeout(() => {
        uploadController.abort();
      }, 90_000);

      let blobResp: any;
      try {
        blobResp = await uploadPromise;
      } finally {
        window.clearTimeout(uploadTimeoutId);
      }

      if (!blobResp) {
        throw new Error("Upload failed: no response from server");
      }

      if (!blobResp.url) {
        throw new Error("Upload failed: invalid response format from server");
      }

      const uploadDuration = Date.now() - startTime;
      console.log(`✓ Uploaded ${formatBytes(encryptedBlobLocal.size)} in ${uploadDuration}ms`);

      setUploadedBlob({
        url: blobResp.url,
        downloadUrl: blobResp.downloadUrl || undefined,
        pathname: blobResp.pathname || pathname
      });

      setPreparedPayload({
        encryptedBlob: encryptedBlobLocal,
        rawFileKeyBase64: rawKeyBase64,
        fileInfos,
        fileNonceBase64,
        clipboardTextEncrypted: undefined
      });

      setSuccessMessage(`✓ Encrypted ${files.length} file${files.length === 1 ? "" : "s"} uploaded successfully!`);
      setStatus({ text: "Ready to send. Select recipients below.", kind: "success" });
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      console.error("Upload error:", errorMsg);
      
      let userMessage = "Upload failed. ";
      if (errorMsg.includes("abort") || errorMsg.includes("timeout")) {
        userMessage += "Request timed out. Check your internet connection and try again.";
      } else if (errorMsg.includes("network")) {
        userMessage += "Network error. Check your connection and try again.";
      } else if (errorMsg.includes("BLOB_READ_WRITE_TOKEN")) {
        userMessage += "Vercel Blob is not configured. Contact administrator.";
      } else {
        userMessage += errorMsg || "Unknown error occurred.";
      }
      
      setStatus({ text: userMessage, kind: "error" });
      setPreparedPayload(null);
      setUploadedBlob(null);
      setSuccessMessage(null);
    } finally {
      setIsUploading(false);
    }
  };

  const searchRecipients = async () => {
    if (!session || !searchQuery.trim()) {
      setSearchResults([]);
      setHasSearched(false);
      return;
    }
    setBusy(true);
    try {
      const data = await apiJson<{ users: User[] }>(
        `/api/rooms/${session.roomId}/users/search?q=${encodeURIComponent(searchQuery)}&userId=${encodeURIComponent(session.userId)}`
      );
      setSearchResults(data.users);
      setHasSearched(true);
      if (!data.users.length) {
        setStatus({ text: `No active user found for "${searchQuery.trim()}".`, kind: "error" });
      } else {
        setStatus({ text: "" });
      }
    } catch (error) {
      setStatus({ text: errorMessage(error), kind: "error" });
    } finally {
      setBusy(false);
    }
  };

  const toggleRecipient = (recipient: User) => {
    setSelectedRecipients((current) =>
      current.some((item) => item.id === recipient.id)
        ? current.filter((item) => item.id !== recipient.id)
        : [...current, recipient]
    );
  };

  const sendFile = async () => {
    if (!session || !identity) return;
    const hasFiles = selectedFiles.length > 0;
    const hasClipboard = !!clipboardText.trim();
    if (!hasFiles && !hasClipboard) {
      setStatus({ text: "Add at least one file or clipboard text.", kind: "error" });
      return;
    }
    if (selectedRecipients.length === 0) {
      setStatus({ text: "Select at least one recipient.", kind: "error" });
      return;
    }
    if (hasFiles && !session.blobConfigured) {
      setStatus({ text: "File uploads are not configured. Add BLOB_READ_WRITE_TOKEN from your Vercel Blob store.", kind: "error" });
      return;
    }

    const parsedDownloadLimit = Number(downloadLimit);
    const parsedExpiry = Number(expirySeconds);
    if (expiryMode === "downloads" && (!Number.isSafeInteger(parsedDownloadLimit) || parsedDownloadLimit < 1 || parsedDownloadLimit > MAX_DOWNLOAD_LIMIT)) {
      setStatus({ text: `Download limit must be between 1 and ${MAX_DOWNLOAD_LIMIT}.`, kind: "error" });
      return;
    }
    if (expiryMode === "time" && (!Number.isInteger(parsedExpiry) || parsedExpiry < 60 || parsedExpiry > MAX_EXPIRY_SECONDS)) {
      setStatus({ text: `Expiry must be between 1 minute and ${MAX_EXPIRY_SECONDS / 3600} hours.`, kind: "error" });
      return;
    }
    if ((deletionTrigger === "download" || deletionTrigger === "open" || deletionTrigger === "copy") && expiryMode !== "downloads") {
      setStatus({ text: "Download/Open/Copy deletion requires Downloads mode.", kind: "error" });
      return;
    }
    if (deletionTrigger === "time" && expiryMode !== "time") {
      setStatus({ text: "Time deletion requires Time mode.", kind: "error" });
      return;
    }

    const effectiveContentType: ContentType = hasFiles && hasClipboard ? "both" : hasClipboard ? "clipboard" : "file";

    setBusy(true);
    try {
      setStatus({ text: `Encrypting for ${selectedRecipients.length} recipient${selectedRecipients.length === 1 ? "" : "s"}...` });
      const clipText = hasClipboard ? clipboardText.trim() : undefined;

      let encrypted: {
        encryptedBlob: Blob;
        recipients: Array<{ id: string; metadata: RecipientMetadata }>;
        clipboardTextEncrypted?: string;
        fileInfos: Array<{ name: string; sizeBytes: number }>;
      };

      // If we've already prepared and uploaded the encrypted payload on file selection,
      // reuse that encrypted blob and just wrap the raw file key per recipient here.
      if (preparedPayload && uploadedBlob && hasFiles) {
        setStatus({ text: `Wrapping key for ${selectedRecipients.length} recipient${selectedRecipients.length === 1 ? "" : "s"}...` });
        const rawKeyBytes = fromBase64(preparedPayload.rawFileKeyBase64);
        // Recover the actual file cipher nonce that was used during encryption
        const actualFileNonce = fromBase64(preparedPayload.fileNonceBase64);

        // Encrypt clipboard text with the same file key if needed
        let clipboardCipherNonce: Uint8Array | undefined;
        let finalClipboardEncrypted: string | undefined;
        if (clipText) {
          const fileKeyRaw = rawKeyBytes;
          const fileKey = await subtleCrypto().importKey("raw", exactArrayBuffer(fileKeyRaw), { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
          clipboardCipherNonce = randomBytes(12);
          const clipPlaintext = encoder.encode(clipText);
          const clipCiphertext = await subtleCrypto().encrypt({ name: "AES-GCM", iv: exactArrayBuffer(clipboardCipherNonce) }, fileKey, exactArrayBuffer(clipPlaintext));
          finalClipboardEncrypted = toBase64(clipCiphertext);
        }

        const recipientMetadata = await Promise.all(
          selectedRecipients.map(async (recipient) => {
            const recipientPublicKey = await importPublicKey(recipient.publicKey);
            const ephemeral = await subtleCrypto().generateKey({ name: "ECDH", namedCurve: CURVE }, true, ["deriveBits"]);
            const wrapSalt = randomBytes(16);
            const wrapNonce = randomBytes(12);
            const wrapKey = await deriveWrapKey(ephemeral.privateKey, recipientPublicKey, wrapSalt, ["encrypt"]);
            const wrappedKey = await subtleCrypto().encrypt({ name: "AES-GCM", iv: wrapNonce }, wrapKey, exactArrayBuffer(rawKeyBytes));
            const ephemeralPublic = await subtleCrypto().exportKey("spki", ephemeral.publicKey);

            const metadata: RecipientMetadata = {
              type: CLIP_TYPE,
              version: 1,
              algorithm: "ECDH-HKDF-SHA256-AES-256-GCM",
              curve: CURVE,
              filename: preparedPayload.fileInfos.length === 1 ? preparedPayload.fileInfos[0].name : "shared-files.bin",
              files: preparedPayload.fileInfos.length > 1 ? preparedPayload.fileInfos : undefined,
              hasClipboard: !!clipText,
              sender: { username: session.username, fingerprint: identity.fingerprint },
              recipient: { username: recipient.username, fingerprint: recipient.fingerprint },
              ephemeralPublicKey: { format: "spki", data: toBase64(ephemeralPublic) },
              kdf: { name: "HKDF", hash: "SHA-256", salt: toBase64(wrapSalt), info: toBase64(WRAP_INFO) },
              wrappedKey: { name: "AES-GCM", nonce: toBase64(wrapNonce), data: toBase64(wrappedKey) },
              cipher: { name: "AES-GCM", nonce: toBase64(actualFileNonce) },
              clipboardCipher: clipboardCipherNonce ? { name: "AES-GCM", nonce: toBase64(clipboardCipherNonce) } : undefined
            };

            return { id: recipient.id, metadata };
          })
        );

        encrypted = {
          encryptedBlob: preparedPayload.encryptedBlob,
          recipients: recipientMetadata,
          clipboardTextEncrypted: finalClipboardEncrypted,
          fileInfos: preparedPayload.fileInfos
        };
      } else {
        const result = await encryptForShare(selectedFiles, clipText, selectedRecipients, session, identity);
        encrypted = result as any;
      }

      let blobUrl = "";
      let blobDownloadUrl: string | undefined;
      let blobPathname = "";

      if (hasFiles) {
        if (!session.blobConfigured) {
          throw new Error("File uploads are not configured. Add BLOB_READ_WRITE_TOKEN to your Vercel environment and redeploy.");
        }

        // If the blob was already uploaded during file selection, reuse it
        if (uploadedBlob) {
          blobUrl = uploadedBlob.url;
          blobDownloadUrl = uploadedBlob.downloadUrl;
          blobPathname = uploadedBlob.pathname;
        } else {
          // Upload now (fallback for cases where auto-upload didn't happen)
          setStatus({ text: `Uploading encrypted payload (${formatBytes(encrypted.encryptedBlob.size)})...` });
          const pathname = `clips/${session.roomId}/${crypto.randomUUID()}-${sanitizeName(selectedFiles[0].name)}.bin`;
          const uploadController = new AbortController();
          const uploadTimeoutId = window.setTimeout(() => uploadController.abort(), 60_000);

          let blob;
          try {
            const uploadPromise = upload(pathname, encrypted.encryptedBlob, {
              access: "private",
              handleUploadUrl: "/api/upload",
              clientPayload: JSON.stringify({ roomId: session.roomId, userId: session.userId }),
              abortSignal: uploadController.signal
            });
            const timeoutPromise = new Promise<never>((_, reject) => {
              window.setTimeout(() => {
                uploadController.abort();
                reject(new Error("Upload timed out. Check your internet connection and try again."));
              }, 65_000);
            });
            blob = await Promise.race([uploadPromise, timeoutPromise]);
          } catch (uploadError) {
            if (uploadError instanceof Error) {
              if (uploadError.message.includes("abort") || uploadError.message.includes("timeout")) {
                throw new Error("Upload timed out. Please check your internet and try again.");
              }
              if (uploadError.message.includes("not configured") || uploadError.message.includes("BLOB_READ_WRITE_TOKEN")) {
                throw new Error("Vercel Blob storage is not configured. Add BLOB_READ_WRITE_TOKEN to your .env.local and restart the dev server.");
              }
              throw uploadError;
            }
            throw new Error("File upload failed. Please check your connection and try again.");
          } finally {
            window.clearTimeout(uploadTimeoutId);
          }

          blobUrl = blob.url;
          blobDownloadUrl = "downloadUrl" in blob ? blob.downloadUrl : undefined;
          blobPathname = blob.pathname;
        }
      }

      setStatus({ text: "Registering expiring access..." });
      await apiJson(`/api/rooms/${session.roomId}/clips`, {
        method: "POST",
        body: JSON.stringify({
          senderId: session.userId,
          recipients: encrypted.recipients,
          contentType: effectiveContentType,
          originalName: hasFiles ? (selectedFiles.length === 1 ? selectedFiles[0].name : `${selectedFiles.length} files`) : "clipboard",
          files: encrypted.fileInfos,
          clipboardTextEncrypted: encrypted.clipboardTextEncrypted,
          sizeBytes: totalFileSize + (clipText ? new TextEncoder().encode(clipText).length : 0),
          encryptedSizeBytes: hasFiles ? encrypted.encryptedBlob.size : 0,
          blobUrl,
          blobDownloadUrl,
          blobPathname,
          expiryMode,
          deletionTrigger,
          downloadLimit:
            deletionTrigger === "download"
              ? downloadLimit
              : deletionTrigger === "time"
                ? "0"
                : "1",
          expiresInSeconds: expiryMode === "time" ? parsedExpiry : MAX_EXPIRY_SECONDS
        })
      });

      // Clear prepared payload after successful send
      setPreparedPayload(null);
      setUploadedBlob(null);
      setStatus({ text: "Encrypted content sent.", kind: "success" });
      setStep("sent");
      await refreshInbox();
    } catch (error) {
      setStatus({ text: errorMessage(error), kind: "error" });
    } finally {
      setBusy(false);
    }
  };

  const openClip = async (clip: InboxClip) => {
    if (!session || !identity) return;
    setBusy(true);
    setStatus({ text: "Downloading encrypted payload..." });
    try {
      const response = await fetch(`/api/clips/${clip.id}/download?userId=${encodeURIComponent(session.userId)}`, { cache: "no-store" });
      if (!response.ok) {
        const data = await response.json().catch(() => null);
        throw new Error(data?.error || "Content is no longer available.");
      }
      const metadata = decodeHeaderJson<RecipientMetadata>(response.headers.get("X-Clip-Metadata"));
      const responseContentType = response.headers.get("X-Content-Type") || "file";

      let encrypted: ArrayBuffer;
      let clipboardEncrypted: string | undefined;

      if (responseContentType === "clipboard") {
        // Clipboard-only: body is JSON
        const body = await response.json() as { clipboardTextEncrypted?: string };
        encrypted = new ArrayBuffer(0);
        clipboardEncrypted = body.clipboardTextEncrypted;
      } else {
        encrypted = await response.arrayBuffer();
        // For "both" mode, clipboard text is in a header
        const clipHeader = response.headers.get("X-Clipboard-Text");
        if (clipHeader) {
          try {
            clipboardEncrypted = decodeHeaderJson<string>(clipHeader);
          } catch {
            // Ignore malformed clipboard header
          }
        }
      }

      setStatus({ text: "Decrypting in this browser..." });
      const result = await decryptClip(metadata, encrypted, identity, clipboardEncrypted);

      // Download files
      for (const file of result.files) {
        downloadBuffer(file.data, file.name);
      }

      // Handle clipboard text
      if (result.clipboardText) {
        await navigator.clipboard.writeText(result.clipboardText).catch(() => undefined);
      }

      const parts: string[] = [];
      if (result.files.length) parts.push(`${result.files.length} file${result.files.length > 1 ? "s" : ""} downloaded`);
      if (result.clipboardText) parts.push("clipboard copied");
      setStatus({ text: parts.join(", ") + ".", kind: "success" });
      await refreshInbox();
    } catch (error) {
      setStatus({ text: error instanceof Error ? error.message : "Download failed.", kind: "error" });
      await refreshInbox().catch(() => undefined);
    } finally {
      setBusy(false);
    }
  };

  const resetSend = () => {
    setSelectedFiles([]);
    setClipboardText("");
    setContentType("file");
    setDeletionTrigger("download");
    setSelectedRecipients([]);
    setSearchResults([]);
    setSearchQuery("");
    setExpiryMode("downloads");
    setDownloadLimit("1");
    setExpirySeconds("3600");
    setPreparedPayload(null);
    setUploadedBlob(null);
    setIsUploading(false);
    setSuccessMessage(null);
    setStep("file");
    setStatus({ text: "" });
    if (inputRef.current) inputRef.current.value = "";
  };

  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="topbar-inner">
          <div className="brand">
            <Image src={logo} alt="FileSn4p" width={154} height={42} priority />
          </div>
          <div className="nav-actions">
            {session && identity ? (
              <div className="identity-pill">
                <strong>{session.username}</strong>
                <span>{identity.fingerprint}</span>
              </div>
            ) : null}
            <button className="icon-button" type="button" onClick={toggleTheme} aria-label="Toggle theme">
              {theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}
            </button>
            {session ? (
              <button className="icon-button" type="button" onClick={logout} aria-label="Leave lobby">
                <LogOut size={18} />
              </button>
            ) : null}
          </div>
        </div>
      </header>

      <div className="screen">
        <AnimatePresence mode="wait">
          {!session ? (
            <motion.section
              key="login"
              className="login-grid"
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -12 }}
              transition={{ duration: 0.24 }}
            >
              <div className="hero-panel">
                <div className="hero-copy">
                  <span className="eyebrow">
                    <ShieldCheck size={16} />
                    Browser encrypted
                  </span>
                  <h1>FileSn4p</h1>
                  <p>Private short-lived file transfer for real work: simple enough for anyone to use, strict enough for sensitive handoffs.</p>
                </div>
                <div className="feature-stack" aria-label="Security and product details">
                  <div className="feature-row">
                    <ShieldCheck size={22} />
                    <div>
                      <strong>End-to-end encrypted</strong>
                      <span>AES-256-GCM protects the file, while ECDH P-256 and HKDF-SHA256 wrap the file key for each recipient.</span>
                    </div>
                  </div>
                  <div className="feature-row">
                    <FileText size={22} />
                    <div>
                      <strong>Zero-knowledge storage</strong>
                      <span>The server stores ciphertext only. Private keys stay in the current browser tab and are never sent to FileSn4p.</span>
                    </div>
                  </div>
                  <div className="feature-row">
                    <Users size={22} />
                    <div>
                      <strong>Private recipient discovery</strong>
                      <span>No public online roster. You search for the person you intend to send to, then verify their fingerprint.</span>
                    </div>
                  </div>
                  <div className="feature-row">
                    <UploadCloud size={22} />
                    <div>
                      <strong>Self-destructing access</strong>
                      <span>Choose a download limit (up to 5) or a time limit (up to 4 hours). Delete after open, copy, download, or time.</span>
                    </div>
                  </div>
                  <div className="feature-row">
                    <Clipboard size={22} />
                    <div>
                      <strong>Clipboard sharing</strong>
                      <span>Share text clips alongside or instead of files, with the same encryption and expiry rules.</span>
                    </div>
                  </div>
                </div>
              </div>

              <form className="auth-panel" onSubmit={login}>
                <h2 className="panel-title">Enter Lobby</h2>
                <p className="muted">Choose a temporary display name.</p>
                <div className="field">
                  <label htmlFor="username">Username</label>
                  <input
                    id="username"
                    className="input"
                    value={username}
                    onChange={(event) => setUsername(event.target.value)}
                    maxLength={32}
                    pattern="[A-Za-z0-9_.\- ]{1,32}"
                    autoComplete="nickname"
                    required
                  />
                  <p className="hint-text">Letters, numbers, spaces, dots, dashes, and underscores.</p>
                </div>
                <button className="button" type="submit" disabled={busy || !username.trim()}>
                  <ShieldCheck size={18} />
                  Enter FileSn4p
                </button>
                <p className={`status ${status.kind || ""}`} role="status" aria-live="polite">
                  {status.text}
                </p>
              </form>
            </motion.section>
          ) : (
            <motion.section
              key="workspace"
              className="workspace"
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -12 }}
              transition={{ duration: 0.24 }}
            >
              <div className="workspace-panel">
                {!session.blobConfigured ? (
                  <div className="config-banner" role="alert">
                    <AlertCircle size={18} />
                    <span>Add <strong>BLOB_READ_WRITE_TOKEN</strong> in Vercel, then redeploy to enable file sharing.</span>
                  </div>
                ) : null}
                <div className="tabs" role="tablist" aria-label="Workspace tabs">
                  <button className={`tab ${tab === "send" ? "active" : ""}`} type="button" onClick={() => setTab("send")}>
                    <Send size={16} />
                    Send
                  </button>
                  <button
                    className={`tab ${tab === "inbox" ? "active" : ""}`}
                    type="button"
                    onClick={() => {
                      setTab("inbox");
                      refreshInbox().catch(() => undefined);
                    }}
                  >
                    <Inbox size={16} />
                    Inbox
                    {inbox.length ? <span className="badge">{inbox.length}</span> : null}
                  </button>
                </div>

                <AnimatePresence mode="wait">
                  {tab === "send" ? (
                    <motion.div key={`send-${step}`} initial={{ opacity: 0, x: 12 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -12 }}>
                      {step === "file" ? (
                        <>
                          <div className="section-heading">
                            <div>
                              <h2>Select Content</h2>
                              <p>Add files and/or clipboard text to share.</p>
                            </div>
                            <span className="step-badge">1</span>
                          </div>

                          {/* Content type selector */}
                          <div className="policy-box">
                            <div className="policy-switch" role="radiogroup" aria-label="Content type">
                              <button
                                className={`policy-choice ${contentType === "file" ? "active" : ""}`}
                                type="button"
                                role="radio"
                                aria-checked={contentType === "file"}
                                onClick={() => setContentType("file")}
                              >
                                <FileText size={14} />
                                Files
                              </button>
                              <button
                                className={`policy-choice ${contentType === "clipboard" ? "active" : ""}`}
                                type="button"
                                role="radio"
                                aria-checked={contentType === "clipboard"}
                                onClick={() => setContentType("clipboard")}
                              >
                                <Clipboard size={14} />
                                Clipboard
                              </button>
                              <button
                                className={`policy-choice ${contentType === "both" ? "active" : ""}`}
                                type="button"
                                role="radio"
                                aria-checked={contentType === "both"}
                                onClick={() => setContentType("both")}
                              >
                                <FileText size={14} />
                                +
                                <Clipboard size={14} />
                              </button>
                            </div>
                          </div>

                          {/* File upload zone */}
                          {(contentType === "file" || contentType === "both") && (
                            <>
                              <div
                                className={`upload-zone ${dragging ? "dragging" : ""}`}
                                role="button"
                                tabIndex={0}
                                onClick={() => inputRef.current?.click()}
                                onKeyDown={(event) => {
                                  if (event.key === "Enter" || event.key === " ") inputRef.current?.click();
                                }}
                                onDragOver={(event) => {
                                  event.preventDefault();
                                  setDragging(true);
                                }}
                                onDragLeave={() => setDragging(false)}
                                onDrop={(event) => {
                                  event.preventDefault();
                                  setDragging(false);
                                  if (event.dataTransfer.files.length) addFiles(event.dataTransfer.files);
                                }}
                              >
                                <div className="upload-zone-inner">
                                  <UploadCloud size={34} />
                                  <strong>Drop files here</strong>
                                  <span className="muted">Max {formatBytes(MAX_FILE_SIZE_BYTES)} total | {selectedFiles.length} file{selectedFiles.length === 1 ? "" : "s"} selected</span>
                                </div>
                                <input
                                  ref={inputRef}
                                  hidden
                                  type="file"
                                  multiple
                                  onChange={(event) => {
                                    if (event.target.files?.length) addFiles(event.target.files);
                                  }}
                                />
                              </div>

                              {selectedFiles.length > 0 && (
                                <div className="file-list">
                                  {selectedFiles.map((file, index) => (
                                    <div className="file-card" key={`${file.name}-${index}`}>
                                      <span className="file-icon"><FileText size={22} /></span>
                                      <div className="file-meta">
                                        <strong>{file.name}</strong>
                                        <span>{formatBytes(file.size)}</span>
                                      </div>
                                      <button className="icon-button" type="button" onClick={() => removeFile(index)} aria-label={`Remove ${file.name}`}>
                                        <X size={18} />
                                      </button>
                                    </div>
                                  ))}
                                  <p className="hint-text">Total: {formatBytes(totalFileSize)} / {formatBytes(MAX_FILE_SIZE_BYTES)}</p>
                                </div>
                              )}
                            </>
                          )}

                          {/* Clipboard text area */}
                          {(contentType === "clipboard" || contentType === "both") && (
                            <div className="field">
                              <label htmlFor="clipboardText">Clipboard Text</label>
                              <textarea
                                id="clipboardText"
                                className="input"
                                rows={4}
                                maxLength={MAX_CLIPBOARD_TEXT_BYTES}
                                value={clipboardText}
                                onChange={(event) => setClipboardText(event.target.value)}
                                placeholder="Enter text to share via clipboard..."
                              />
                              <p className="hint-text">{clipboardText.length > 0 ? `${formatBytes(new TextEncoder().encode(clipboardText).length)}` : `Max ${MAX_CLIPBOARD_TEXT_BYTES / 1024} KB`}</p>
                            </div>
                          )}

                          {/* Deletion trigger */}
                          <div className="policy-box">
                            <label className="field-label">Delete after</label>
                            <div className="policy-switch" role="radiogroup" aria-label="Deletion trigger">
                              <button
                                className={`policy-choice ${deletionTrigger === "download" ? "active" : ""}`}
                                type="button"
                                role="radio"
                                aria-checked={deletionTrigger === "download"}
                                onClick={() => {
                                  setDeletionTrigger("download");
                                  setExpiryMode("downloads");
                                }}
                              >
                                <Download size={14} />
                                Download
                              </button>
                              <button
                                className={`policy-choice ${deletionTrigger === "open" ? "active" : ""}`}
                                type="button"
                                role="radio"
                                aria-checked={deletionTrigger === "open"}
                                onClick={() => {
                                  setDeletionTrigger("open");
                                  setExpiryMode("downloads");
                                }}
                              >
                                <Eye size={14} />
                                Open
                              </button>
                              <button
                                className={`policy-choice ${deletionTrigger === "copy" ? "active" : ""}`}
                                type="button"
                                role="radio"
                                aria-checked={deletionTrigger === "copy"}
                                onClick={() => {
                                  setDeletionTrigger("copy");
                                  setExpiryMode("downloads");
                                }}
                              >
                                <Copy size={14} />
                                Copy
                              </button>
                              <button
                                className={`policy-choice ${deletionTrigger === "time" ? "active" : ""}`}
                                type="button"
                                role="radio"
                                aria-checked={deletionTrigger === "time"}
                                onClick={() => {
                                  setDeletionTrigger("time");
                                  setExpiryMode("time");
                                }}
                              >
                                <Clock size={14} style={{ display: "inline", verticalAlign: "middle" }} />
                                Time
                              </button>
                            </div>
                          </div>

                          {/* Expiry policy */}
                          <div className="policy-box">
                            <div className="policy-switch" role="radiogroup" aria-label="Expiry policy">
                              <button
                                className={`policy-choice ${expiryMode === "downloads" ? "active" : ""}`}
                                type="button"
                                role="radio"
                                aria-checked={expiryMode === "downloads"}
                                onClick={() => {
                                  setExpiryMode("downloads");
                                  if (deletionTrigger === "time") setDeletionTrigger("download");
                                }}
                              >
                                Downloads
                              </button>
                              <button
                                className={`policy-choice ${expiryMode === "time" ? "active" : ""}`}
                                type="button"
                                role="radio"
                                aria-checked={expiryMode === "time"}
                                onClick={() => {
                                  setExpiryMode("time");
                                  if (deletionTrigger !== "time") setDeletionTrigger("time");
                                }}
                              >
                                Time
                              </button>
                            </div>

                            {expiryMode === "downloads" ? (
                              <div className="field">
                                <label htmlFor="downloadLimit">Download limit</label>
                                <input
                                  id="downloadLimit"
                                  className="number-input"
                                  value={downloadLimit}
                                  min={1}
                                  max={MAX_DOWNLOAD_LIMIT}
                                  step={1}
                                  inputMode="numeric"
                                  type="number"
                                  onChange={(event) => setDownloadLimit(event.target.value)}
                                />
                                <p className="hint-text">1 to {MAX_DOWNLOAD_LIMIT} downloads. Access ends after this many.</p>
                              </div>
                            ) : (
                              <div className="field">
                                <label htmlFor="expirySeconds">Expiry time (seconds)</label>
                                <input
                                  id="expirySeconds"
                                  className="number-input"
                                  value={expirySeconds}
                                  min={60}
                                  max={MAX_EXPIRY_SECONDS}
                                  step={60}
                                  inputMode="numeric"
                                  type="number"
                                  onChange={(event) => setExpirySeconds(event.target.value)}
                                />
                                <p className="hint-text">1 minute to {MAX_EXPIRY_SECONDS / 3600} hours.</p>
                              </div>
                            )}
                          </div>

                          <button className="button" type="button" disabled={!(selectedFiles.length > 0 || clipboardText.trim())} onClick={() => setStep("recipients")}>
                            Continue
                            <Users size={18} />
                          </button>
                        </>
                      ) : null}

                      {step === "recipients" ? (
                        <>
                          <button className="button secondary" type="button" onClick={() => setStep("file")}>
                            <ArrowLeft size={18} />
                            Back
                          </button>
                          <div className="section-heading">
                            <div>
                              <h2>Select Recipients</h2>
                              <p>{selectedRecipients.length} selected</p>
                            </div>
                            <span className="step-badge">2</span>
                          </div>

                          <div className="search-row">
                            <input
                              className="input"
                              value={searchQuery}
                              maxLength={32}
                              onChange={(event) => {
                                setSearchQuery(event.target.value);
                                setHasSearched(false);
                              }}
                              onKeyDown={(event) => {
                                if (event.key === "Enter") {
                                  event.preventDefault();
                                  searchRecipients();
                                }
                              }}
                              placeholder="Search username"
                            />
                            <button className="icon-button" type="button" onClick={searchRecipients} aria-label="Search recipients">
                              <Search size={18} />
                            </button>
                          </div>

                          {selectedRecipients.length ? (
                            <div className="selected-strip">
                              <h3>Selected Recipients</h3>
                              <div className="recipient-tags">
                                {selectedRecipients.map((recipient) => (
                                  <motion.span className="recipient-tag" key={recipient.id} layout>
                                    <span>{recipient.username}</span>
                                    <button type="button" onClick={() => toggleRecipient(recipient)} aria-label={`Remove ${recipient.username}`}>
                                      <X size={14} />
                                    </button>
                                  </motion.span>
                                ))}
                              </div>
                            </div>
                          ) : null}

                          <div className="recipient-results">
                            {searchResults.length ? (
                              searchResults.map((recipient) => {
                                const selected = selectedIds.has(recipient.id);
                                return (
                                  <motion.button
                                    layout
                                    key={recipient.id}
                                    className={`recipient-card ${selected ? "selected" : ""}`}
                                    type="button"
                                    onClick={() => toggleRecipient(recipient)}
                                  >
                                    <span className="avatar">{recipient.username.slice(0, 1).toUpperCase()}</span>
                                    <span className="recipient-copy">
                                      <strong>{recipient.username}</strong>
                                      <span>{recipient.fingerprint}</span>
                                    </span>
                                    <span className="checkmark">
                                      <Check size={16} />
                                    </span>
                                  </motion.button>
                                );
                              })
                            ) : (
                              <div className="empty-state">
                                {hasSearched ? `No user found for "${searchQuery.trim()}".` : "Search by username to find a recipient."}
                              </div>
                            )}
                          </div>

                          <button className="button teal" type="button" disabled={busy || !selectedRecipients.length} onClick={sendFile}>
                            <Send size={18} />
                            Send Encrypted
                          </button>
                        </>
                      ) : null}

                      {step === "sent" ? (
                        <div className="empty-state">
                          <div>
                            <Check size={34} />
                            <h2>Sent</h2>
                            <p className="muted">Recipients can open it from their inbox while the policy allows.</p>
                            <button className="button" type="button" onClick={resetSend}>
                              Send Another
                            </button>
                          </div>
                        </div>
                      ) : null}
                    </motion.div>
                  ) : (
                    <motion.div key="inbox" initial={{ opacity: 0, x: 12 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -12 }}>
                      <div className="section-heading">
                        <div>
                          <h2>Inbox</h2>
                          <p>Content shared with your active browser key.</p>
                        </div>
                        <button className="icon-button" type="button" onClick={() => refreshInbox().catch(() => undefined)} aria-label="Refresh inbox">
                          <Inbox size={18} />
                        </button>
                      </div>
                      <div className="inbox-list">
                        {inbox.length ? (
                          inbox.map((clip) => (
                            <motion.div className="inbox-item" key={clip.id} layout>
                              <span className="file-icon">
                                {clip.contentType === "clipboard" ? <Clipboard size={20} /> : <FileText size={20} />}
                              </span>
                              <div className="inbox-copy">
                                <strong>
                                  {clip.contentType === "clipboard"
                                    ? "Clipboard"
                                    : clip.files.length > 1
                                      ? `${clip.files.length} files`
                                      : clip.filename}
                                  {clip.hasClipboard && clip.contentType !== "clipboard" ? " + clipboard" : ""}
                                </strong>
                                <span>
                                  From <strong>{clip.senderName}</strong>
                                  {!clip.senderVerified && <em className="unknown-warning"> (unknown)</em>}
                                  {" | "}{formatBytes(clip.sizeBytes)}{" | "}
                                  {clip.expiryMode === "time"
                                    ? `expires in ${formatTimeLeft(clip.expiresAt)}`
                                    : `${clip.viewsLeft} download${clip.viewsLeft === 1 ? "" : "s"} left`}
                                  {" | "}
                                  delete after {clip.deletionTrigger}
                                </span>
                              </div>
                              <div className="inbox-actions">
                                <button className="button" type="button" disabled={busy} onClick={() => openClip(clip)}>
                                  {clip.contentType === "clipboard" ? <Copy size={18} /> : <Download size={18} />}
                                  Open
                                </button>
                              </div>
                            </motion.div>
                          ))
                        ) : (
                          <div className="empty-state">No content yet.</div>
                        )}
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>

                <p className={`status ${status.kind || ""}`} role="status" aria-live="polite">
                  {status.text}
                </p>
              </div>
            </motion.section>
          )}
        </AnimatePresence>
      </div>

      <AnimatePresence>
        {alertFile ? (
          <motion.div className="alert-overlay" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
            <motion.div
              className="alert-modal"
              role="alertdialog"
              aria-modal="true"
              aria-labelledby="file-alert-title"
              initial={{ opacity: 0, y: 14, scale: 0.98 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: 14, scale: 0.98 }}
            >
              <AlertCircle size={34} />
              <h2 id="file-alert-title">Size Limit Exceeded</h2>
              <p>
                {alertFile.name} would exceed the {formatBytes(MAX_FILE_SIZE_BYTES)} total size limit.
              </p>
              <button className="button" type="button" onClick={() => setAlertFile(null)}>
                Got It
              </button>
            </motion.div>
          </motion.div>
        ) : null}
      </AnimatePresence>

      <AnimatePresence>
        {successMessage ? (
          <motion.div className="alert-overlay" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
            <motion.div
              className="alert-modal success-modal"
              role="alertdialog"
              aria-modal="true"
              aria-labelledby="success-alert-title"
              initial={{ opacity: 0, y: 14, scale: 0.98 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: 14, scale: 0.98 }}
            >
              <Check size={50} color="#34d399" />
              <h2 id="success-alert-title" style={{ color: "#34d399" }}>Files Uploaded Successfully</h2>
              <p>{successMessage}</p>
              <p className="muted" style={{ fontSize: "0.85rem", marginTop: "0.5rem" }}>Now select a recipient to send your files.</p>
              <button className="button" type="button" onClick={() => {
                setSuccessMessage(null);
                setStep("recipients");
              }}>
                Select Recipients
              </button>
            </motion.div>
          </motion.div>
        ) : null}
      </AnimatePresence>
    </main>
  );
}
