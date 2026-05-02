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

export type ShareRecord = {
  id: string;
  roomId: string;
  senderId: string;
  senderName: string;
  recipientIds: string[];
  clipIds: string[];
  originalName: string;
  sizeBytes: number;
  encryptedSizeBytes: number;
  blobUrl: string;
  blobDownloadUrl?: string;
  blobPathname: string;
  createdAt: number;
  expiresAt: number;
  downloadLimit: number;
};

export type ClipRecord = {
  id: string;
  shareId: string;
  roomId: string;
  senderId: string;
  senderName: string;
  recipientId: string;
  originalName: string;
  sizeBytes: number;
  metadata: RecipientMetadata;
  createdAt: number;
  expiresAt: number;
};

export type InboxClip = {
  id: string;
  senderName: string;
  filename: string;
  sizeBytes: number;
  createdAt: number;
  expiresAt: number;
  viewsLeft: number;
};

