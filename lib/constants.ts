export const APP_NAME = "FileSn4p";
export const PUBLIC_LOBBY_ID = "LOBBY1";

export const MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024;
export const ENCRYPTION_OVERHEAD_BYTES = 128 * 1024;
export const MAX_CLIPBOARD_TEXT_BYTES = 100 * 1024; // 100 KB text clipboard limit

// Expiry & download constraints
export const MIN_DOWNLOAD_LIMIT = 1;
export const MAX_DOWNLOAD_LIMIT = 5;
export const MIN_EXPIRY_SECONDS = 60;
export const MAX_EXPIRY_SECONDS = 4 * 60 * 60; // 4 hours
export const BACKEND_MAX_TTL_SECONDS = 24 * 60 * 60; // 24-hour hard backend ceiling

export const ACTIVE_USER_SECONDS = 45;
export const STALE_USER_SECONDS = 120;
export const MAX_ROOM_USERS = 100;
export const MAX_RECIPIENTS = 100;
export const SHARE_CLEANUP_GRACE_SECONDS = 24 * 60 * 60;

export const PUBLIC_KEY_TYPE = "filesn4p-live-public-key";
export const CLIP_TYPE = "filesn4p-live-clip";
export const CURVE = "P-256";

export type ContentType = "file" | "clipboard" | "both";
export type ExpiryMode = "downloads" | "time";
export type DeletionTrigger = "download" | "open" | "copy" | "time";
