import type { ContentType, DeletionTrigger, ExpiryMode } from "@/lib/constants";

export type PublicKeyDoc = {
  type: string;
  version: number;
  algorithm: "ECDH";
  curve: "P-256";
  publicKey: {
    format: "spki";
    data: string;
  };
};

export type RecipientMetadata = {
  type: string;
  version: number;
  algorithm: string;
  curve: "P-256";
  filename: string;
  files?: Array<{ name: string; sizeBytes: number }>;
  hasClipboard?: boolean;
  sender: {
    username: string;
    fingerprint: string;
  };
  recipient: {
    username: string;
    fingerprint: string;
  };
  ephemeralPublicKey: {
    format: "spki";
    data: string;
  };
  kdf: {
    name: "HKDF";
    hash: "SHA-256";
    salt: string;
    info: string;
  };
  wrappedKey: {
    name: "AES-GCM";
    nonce: string;
    data: string;
  };
  cipher: {
    name: "AES-GCM";
    nonce: string;
  };
  clipboardCipher?: {
    name: "AES-GCM";
    nonce: string;
  };
};

export type UserRecord = {
  id: string;
  roomId: string;
  username: string;
  publicKey: PublicKeyDoc;
  fingerprint: string;
  joinedAt: number;
  lastSeen: number;
};

export type FileInfo = {
  name: string;
  sizeBytes: number;
};

export type ShareRecord = {
  id: string;
  roomId: string;
  senderId: string;
  senderName: string;
  senderFingerprint: string;
  recipientIds: string[];
  clipIds: string[];
  contentType: ContentType;
  originalName: string;
  files: FileInfo[];
  clipboardTextEncrypted?: string; // base64-encoded encrypted clipboard text
  sizeBytes: number;
  encryptedSizeBytes: number;
  blobUrl: string;
  blobDownloadUrl?: string;
  blobPathname: string;
  createdAt: number;
  expiresAt: number;
  expiryMode: ExpiryMode;
  deletionTrigger: DeletionTrigger;
  downloadLimit: number;
};

export type ClipRecord = {
  id: string;
  shareId: string;
  roomId: string;
  senderId: string;
  senderName: string;
  senderFingerprint: string;
  recipientId: string;
  contentType: ContentType;
  originalName: string;
  files: FileInfo[];
  hasClipboard: boolean;
  sizeBytes: number;
  metadata: RecipientMetadata;
  createdAt: number;
  expiresAt: number;
  expiryMode?: ExpiryMode;
  deletionTrigger?: DeletionTrigger;
};

export type InboxClip = {
  id: string;
  senderName: string;
  senderFingerprint: string;
  senderVerified: boolean;
  contentType: ContentType;
  filename: string;
  files: FileInfo[];
  hasClipboard: boolean;
  sizeBytes: number;
  createdAt: number;
  expiresAt: number;
  expiryMode: ExpiryMode;
  deletionTrigger: DeletionTrigger;
  viewsLeft: number;
};
