"use client";

import { upload } from "@vercel/blob/client";
import { AnimatePresence, motion } from "framer-motion";
import {
  AlertCircle,
  ArrowLeft,
  Check,
  Download,
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
  MAX_EXPIRY_SECONDS,
  MAX_FILE_SIZE_BYTES,
  PUBLIC_KEY_TYPE
} from "@/lib/constants";
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

async function encryptForShare(file: File, recipients: User[], session: Session, identity: Identity) {
  const fileKey = await subtleCrypto().generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const fileNonce = randomBytes(12);
  const plaintext = await file.arrayBuffer();
  const ciphertext = await subtleCrypto().encrypt({ name: "AES-GCM", iv: fileNonce }, fileKey, plaintext);
  const rawFileKey = await subtleCrypto().exportKey("raw", fileKey);

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
        filename: sanitizeName(file.name),
        sender: { username: session.username, fingerprint: identity.fingerprint },
        recipient: { username: recipient.username, fingerprint: recipient.fingerprint },
        ephemeralPublicKey: { format: "spki", data: toBase64(ephemeralPublic) },
        kdf: { name: "HKDF", hash: "SHA-256", salt: toBase64(wrapSalt), info: toBase64(WRAP_INFO) },
        wrappedKey: { name: "AES-GCM", nonce: toBase64(wrapNonce), data: toBase64(wrappedKey) },
        cipher: { name: "AES-GCM", nonce: toBase64(fileNonce) }
      };

      return { id: recipient.id, metadata };
    })
  );

  return {
    encryptedBlob: new Blob([ciphertext], { type: "application/octet-stream" }),
    recipients: recipientMetadata
  };
}

async function decryptClip(metadata: RecipientMetadata, encrypted: ArrayBuffer, identity: Identity) {
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
  return subtleCrypto().decrypt({ name: "AES-GCM", iv: fromBase64(metadata.cipher.nonce) }, fileKey, encrypted);
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
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [expiryMode, setExpiryMode] = useState<ExpiryMode>("downloads");
  const [downloadLimit, setDownloadLimit] = useState("1");
  const [expiryMinutes, setExpiryMinutes] = useState("1");
  const [searchQuery, setSearchQuery] = useState("");
  const [hasSearched, setHasSearched] = useState(false);
  const [searchResults, setSearchResults] = useState<User[]>([]);
  const [selectedRecipients, setSelectedRecipients] = useState<User[]>([]);
  const [inbox, setInbox] = useState<InboxClip[]>([]);
  const [busy, setBusy] = useState(false);
  const [alertFile, setAlertFile] = useState<{ name: string; size: number } | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const logo = theme === "light" ? "/logo-light.svg" : "/logo-dark.svg";
  const selectedIds = useMemo(() => new Set(selectedRecipients.map((recipient) => recipient.id)), [selectedRecipients]);

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

  const logout = () => {
    setSession(null);
    setIdentity(null);
    setSelectedFile(null);
    setSelectedRecipients([]);
    setSearchResults([]);
    setInbox([]);
    setStep("file");
    setTab("send");
    setStatus({ text: "" });
  };

  const chooseFile = (file: File) => {
    if (file.size > MAX_FILE_SIZE_BYTES) {
      setAlertFile({ name: file.name, size: file.size });
      return;
    }
    setSelectedFile(file);
    setStep("file");
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
    if (!session || !identity || !selectedFile || selectedRecipients.length === 0) return;
    if (!session.blobConfigured) {
      setStatus({ text: "File uploads are not configured. Add BLOB_READ_WRITE_TOKEN from your Vercel Blob store.", kind: "error" });
      return;
    }

    const parsedDownloadLimit = Number(downloadLimit);
    const parsedExpiry = Number(expiryMinutes);
    if (expiryMode === "downloads" && (!Number.isSafeInteger(parsedDownloadLimit) || parsedDownloadLimit < 1)) {
      setStatus({ text: "Download limit must be at least 1.", kind: "error" });
      return;
    }
    if (expiryMode === "time" && (!Number.isInteger(parsedExpiry) || parsedExpiry < 1 || parsedExpiry > 180)) {
      setStatus({ text: "Expiry must be between 1 and 180 minutes.", kind: "error" });
      return;
    }

    setBusy(true);
    try {
      setStatus({ text: `Encrypting for ${selectedRecipients.length} recipient${selectedRecipients.length === 1 ? "" : "s"}...` });
      const encrypted = await encryptForShare(selectedFile, selectedRecipients, session, identity);

      setStatus({ text: "Uploading encrypted payload..." });
      const pathname = `clips/${session.roomId}/${crypto.randomUUID()}-${sanitizeName(selectedFile.name)}.bin`;
      const blob = await upload(pathname, encrypted.encryptedBlob, {
        access: "public",
        handleUploadUrl: "/api/upload",
        clientPayload: JSON.stringify({ roomId: session.roomId, userId: session.userId })
      });

      setStatus({ text: "Registering expiring access..." });
      await apiJson(`/api/rooms/${session.roomId}/clips`, {
        method: "POST",
        body: JSON.stringify({
          senderId: session.userId,
          recipients: encrypted.recipients,
          originalName: selectedFile.name,
          sizeBytes: selectedFile.size,
          encryptedSizeBytes: encrypted.encryptedBlob.size,
          blobUrl: blob.url,
          blobDownloadUrl: "downloadUrl" in blob ? blob.downloadUrl : undefined,
          blobPathname: blob.pathname,
          expiryMode,
          downloadLimit: expiryMode === "downloads" ? downloadLimit : String(Number.MAX_SAFE_INTEGER),
          expiresInSeconds: expiryMode === "time" ? parsedExpiry * 60 : MAX_EXPIRY_SECONDS
        })
      });

      setStatus({ text: "Encrypted file sent.", kind: "success" });
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
        throw new Error(data?.error || "File is no longer available.");
      }
      const metadata = decodeHeaderJson<RecipientMetadata>(response.headers.get("X-Clip-Metadata"));
      const encrypted = await response.arrayBuffer();
      setStatus({ text: "Decrypting in this browser..." });
      const plaintext = await decryptClip(metadata, encrypted, identity);
      downloadBuffer(plaintext, metadata.filename || clip.filename);
      setStatus({ text: "File decrypted.", kind: "success" });
      await refreshInbox();
    } catch (error) {
      setStatus({ text: error instanceof Error ? error.message : "Download failed.", kind: "error" });
      await refreshInbox().catch(() => undefined);
    } finally {
      setBusy(false);
    }
  };

  const resetSend = () => {
    setSelectedFile(null);
    setSelectedRecipients([]);
    setSearchResults([]);
    setSearchQuery("");
    setExpiryMode("downloads");
    setDownloadLimit("1");
    setExpiryMinutes("1");
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
                      <span>Choose either a download limit or a time limit from 1 minute to 3 hours.</span>
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
                              <h2>Select File</h2>
                              <p>Set the download count and expiry before choosing recipients.</p>
                            </div>
                            <span className="step-badge">1</span>
                          </div>

                          {!selectedFile ? (
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
                                const file = event.dataTransfer.files.item(0);
                                if (file) chooseFile(file);
                              }}
                            >
                              <div className="upload-zone-inner">
                                <UploadCloud size={34} />
                                <strong>Drop a file here</strong>
                                <span className="muted">Maximum {formatBytes(MAX_FILE_SIZE_BYTES)}</span>
                              </div>
                              <input
                                ref={inputRef}
                                hidden
                                type="file"
                                onChange={(event) => {
                                  const file = event.target.files?.item(0);
                                  if (file) chooseFile(file);
                                }}
                              />
                            </div>
                          ) : (
                            <div className="file-card">
                              <span className="file-icon">
                                <FileText size={22} />
                              </span>
                              <div className="file-meta">
                                <strong>{selectedFile.name}</strong>
                                <span>{formatBytes(selectedFile.size)}</span>
                              </div>
                              <button className="icon-button" type="button" onClick={() => setSelectedFile(null)} aria-label="Remove file">
                                <X size={18} />
                              </button>
                            </div>
                          )}

                          <div className="policy-box">
                            <div className="policy-switch" role="radiogroup" aria-label="Expiry policy">
                              <button
                                className={`policy-choice ${expiryMode === "downloads" ? "active" : ""}`}
                                type="button"
                                role="radio"
                                aria-checked={expiryMode === "downloads"}
                                onClick={() => setExpiryMode("downloads")}
                              >
                                Downloads
                              </button>
                              <button
                                className={`policy-choice ${expiryMode === "time" ? "active" : ""}`}
                                type="button"
                                role="radio"
                                aria-checked={expiryMode === "time"}
                                onClick={() => setExpiryMode("time")}
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
                                  step={1}
                                  inputMode="numeric"
                                  type="number"
                                  onChange={(event) => setDownloadLimit(event.target.value)}
                                />
                                <p className="hint-text">Minimum 1. File access ends after this many downloads.</p>
                              </div>
                            ) : (
                              <div className="field">
                                <label htmlFor="expiryMinutes">Expiry time</label>
                                <input
                                  id="expiryMinutes"
                                  className="number-input"
                                  value={expiryMinutes}
                                  min={1}
                                  max={180}
                                  step={1}
                                  inputMode="numeric"
                                  type="number"
                                  onChange={(event) => setExpiryMinutes(event.target.value)}
                                />
                                <p className="hint-text">1 minute to 3 hours.</p>
                              </div>
                            )}
                          </div>

                          <button className="button" type="button" disabled={!selectedFile} onClick={() => setStep("recipients")}>
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
                            Send Encrypted File
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
                              Send Another File
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
                          <p>Files shared with your active browser key.</p>
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
                                <FileText size={20} />
                              </span>
                              <div className="inbox-copy">
                                <strong>{clip.filename}</strong>
                                <span>
                                  From {clip.senderName} | {formatBytes(clip.sizeBytes)} |{" "}
                                  {clip.expiryMode === "time"
                                    ? `expires in ${formatTimeLeft(clip.expiresAt)}`
                                    : `${clip.viewsLeft} download${clip.viewsLeft === 1 ? "" : "s"} left`}
                                </span>
                              </div>
                              <div className="inbox-actions">
                                <button className="button" type="button" disabled={busy} onClick={() => openClip(clip)}>
                                  <Download size={18} />
                                  Open
                                </button>
                              </div>
                            </motion.div>
                          ))
                        ) : (
                          <div className="empty-state">No files yet.</div>
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
              <h2 id="file-alert-title">File Too Large</h2>
              <p>
                {alertFile.name} is {formatBytes(alertFile.size)}. The maximum size is {formatBytes(MAX_FILE_SIZE_BYTES)}.
              </p>
              <button className="button" type="button" onClick={() => setAlertFile(null)}>
                Got It
              </button>
            </motion.div>
          </motion.div>
        ) : null}
      </AnimatePresence>
    </main>
  );
}
