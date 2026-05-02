import { del as deleteBlob } from "@vercel/blob";
import { Redis } from "@upstash/redis";
import {
  ACTIVE_USER_SECONDS,
  MAX_ROOM_USERS,
  PUBLIC_LOBBY_ID,
  SHARE_CLEANUP_GRACE_SECONDS,
  STALE_USER_SECONDS
} from "@/lib/constants";
import type { ClipRecord, InboxClip, PublicKeyDoc, RecipientMetadata, ShareRecord, UserRecord } from "@/lib/types";
import { ApiError, nowSeconds } from "@/lib/validation";

type StoredValue<T> = {
  value: T;
  expiresAt?: number;
};

type MemoryStore = {
  values: Map<string, StoredValue<unknown>>;
  sets: Map<string, StoredValue<Set<string>>>;
};

declare global {
  var __filesn4pMemoryStore: MemoryStore | undefined;
}

const redis =
  process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN
    ? new Redis({
        url: process.env.UPSTASH_REDIS_REST_URL,
        token: process.env.UPSTASH_REDIS_REST_TOKEN
      })
    : null;

const memory =
  globalThis.__filesn4pMemoryStore ??
  (globalThis.__filesn4pMemoryStore = {
    values: new Map<string, StoredValue<unknown>>(),
    sets: new Map<string, StoredValue<Set<string>>>()
  });

function roomUsersKey(roomId: string) {
  return `room:${roomId}:users`;
}

function userKey(userId: string) {
  return `user:${userId}`;
}

function inboxKey(userId: string) {
  return `inbox:${userId}`;
}

function clipKey(clipId: string) {
  return `clip:${clipId}`;
}

function shareKey(shareId: string) {
  return `share:${shareId}`;
}

function shareViewsKey(shareId: string) {
  return `share:${shareId}:views`;
}

function rateKey(bucket: string, identity: string, windowSeconds: number) {
  return `rate:${bucket}:${identity}:${Math.floor(nowSeconds() / windowSeconds)}`;
}

function randomId(bytes = 18) {
  return crypto.getRandomValues(new Uint8Array(bytes)).reduce((acc, byte) => acc + byte.toString(16).padStart(2, "0"), "");
}

function secondsUntil(unixSeconds: number) {
  return Math.max(1, unixSeconds - nowSeconds());
}

function isExpired(entry?: StoredValue<unknown>) {
  return !!entry?.expiresAt && entry.expiresAt <= nowSeconds();
}

async function kvGet<T>(key: string): Promise<T | null> {
  if (redis) return redis.get<T>(key);

  const entry = memory.values.get(key);
  if (isExpired(entry)) {
    memory.values.delete(key);
    return null;
  }
  return (entry?.value as T) ?? null;
}

async function kvSet<T>(key: string, value: T, ttlSeconds?: number) {
  if (redis) {
    if (ttlSeconds) await redis.set(key, value, { ex: ttlSeconds });
    else await redis.set(key, value);
    return;
  }
  memory.values.set(key, {
    value,
    expiresAt: ttlSeconds ? nowSeconds() + ttlSeconds : undefined
  });
}

async function kvDel(...keys: string[]) {
  if (!keys.length) return;
  if (redis) {
    await redis.del(...keys);
    return;
  }
  keys.forEach((key) => {
    memory.values.delete(key);
    memory.sets.delete(key);
  });
}

async function setAdd(key: string, value: string) {
  if (redis) {
    await redis.sadd(key, value);
    return;
  }
  const entry = memory.sets.get(key);
  const set = isExpired(entry) || !entry ? new Set<string>() : entry.value;
  set.add(value);
  memory.sets.set(key, { value: set, expiresAt: entry?.expiresAt });
}

async function setRemove(key: string, ...values: string[]) {
  if (redis) {
    if (values.length) await redis.srem(key, ...values);
    return;
  }
  const entry = memory.sets.get(key);
  if (!entry || isExpired(entry)) return;
  values.forEach((value) => entry.value.delete(value));
}

async function setMembers(key: string): Promise<string[]> {
  if (redis) return redis.smembers<string[]>(key);

  const entry = memory.sets.get(key);
  if (isExpired(entry)) {
    memory.sets.delete(key);
    return [];
  }
  return Array.from(entry?.value ?? []);
}

async function setExpire(key: string, ttlSeconds: number) {
  if (redis) {
    await redis.expire(key, ttlSeconds);
    return;
  }
  const entry = memory.sets.get(key);
  if (entry) entry.expiresAt = nowSeconds() + ttlSeconds;
}

async function incrementWithTtl(key: string, ttlSeconds: number) {
  if (redis) {
    const count = await redis.incr(key);
    if (count === 1) await redis.expire(key, ttlSeconds);
    return count;
  }
  const current = (await kvGet<number>(key)) ?? 0;
  const next = current + 1;
  await kvSet(key, next, ttlSeconds);
  return next;
}

async function decrementIfPositive(key: string) {
  if (redis) {
    const result = await redis.eval(
      "local current = tonumber(redis.call('GET', KEYS[1]) or '0'); if current <= 0 then return -1; end; return redis.call('DECR', KEYS[1]);",
      [key],
      []
    );
    return Number(result);
  }

  const current = (await kvGet<number>(key)) ?? 0;
  if (current <= 0) return -1;
  const next = current - 1;
  const existing = memory.values.get(key);
  memory.values.set(key, { value: next, expiresAt: existing?.expiresAt });
  return next;
}

function isActive(user: UserRecord | null) {
  return !!user && user.lastSeen > nowSeconds() - ACTIVE_USER_SECONDS;
}

async function hydrateUsers(roomId: string) {
  const ids = await setMembers(roomUsersKey(roomId));
  const users = await Promise.all(ids.map((id) => kvGet<UserRecord>(userKey(id))));
  return users.filter((user): user is UserRecord => !!user);
}

export async function enforceRateLimit(request: Request, bucket: string, limit: number, windowSeconds: number) {
  const forwarded = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  const identity = forwarded || request.headers.get("x-real-ip") || "local";
  const count = await incrementWithTtl(rateKey(bucket, identity, windowSeconds), windowSeconds + 2);
  if (count > limit) throw new ApiError("Too many requests. Slow down and try again.", 429);
}

export async function createUser(input: {
  username: string;
  publicKey: PublicKeyDoc;
  fingerprint: string;
}) {
  const timestamp = nowSeconds();
  const activeUsers = (await hydrateUsers(PUBLIC_LOBBY_ID)).filter(isActive);

  if (activeUsers.length >= MAX_ROOM_USERS) {
    throw new ApiError("The lobby is full. Try again in a moment.");
  }

  if (activeUsers.some((user) => user.username.toLowerCase() === input.username.toLowerCase())) {
    throw new ApiError("Username is already active in the lobby.");
  }

  const user: UserRecord = {
    id: randomId(),
    roomId: PUBLIC_LOBBY_ID,
    username: input.username,
    publicKey: input.publicKey,
    fingerprint: input.fingerprint,
    joinedAt: timestamp,
    lastSeen: timestamp
  };

  await kvSet(userKey(user.id), user, STALE_USER_SECONDS);
  await setAdd(roomUsersKey(PUBLIC_LOBBY_ID), user.id);
  await setExpire(roomUsersKey(PUBLIC_LOBBY_ID), STALE_USER_SECONDS * 2);

  return user;
}

export async function touchUser(roomId: string, userId: string) {
  const user = await kvGet<UserRecord>(userKey(userId));
  if (!user || user.roomId !== roomId) throw new ApiError("Temporary user is no longer active.", 404);

  user.lastSeen = nowSeconds();
  await kvSet(userKey(userId), user, STALE_USER_SECONDS);
  await setAdd(roomUsersKey(roomId), userId);
  await setExpire(roomUsersKey(roomId), STALE_USER_SECONDS * 2);
  return user;
}

export async function requireActiveUser(roomId: string, userId: string | null | undefined) {
  if (!userId) throw new ApiError("Join the lobby first.", 403);
  const user = await kvGet<UserRecord>(userKey(userId));
  if (!user || user.roomId !== roomId || !isActive(user)) {
    throw new ApiError("Join the lobby first.", 403);
  }
  return user;
}

export async function listUsers(roomId: string, currentUserId: string) {
  await requireActiveUser(roomId, currentUserId);
  const users = (await hydrateUsers(roomId)).filter(isActive);
  users.sort((a, b) => a.username.localeCompare(b.username) || a.joinedAt - b.joinedAt);
  return users;
}

export async function searchUsers(roomId: string, currentUserId: string, query: string) {
  const lowered = query.trim().toLowerCase();
  if (!lowered) return [];
  const users = await listUsers(roomId, currentUserId);
  return users
    .filter((user) => user.id !== currentUserId && user.username.toLowerCase().includes(lowered))
    .slice(0, 50);
}

export async function createShare(input: {
  roomId: string;
  senderId: string;
  recipients: Array<{ id: string; metadata: RecipientMetadata }>;
  originalName: string;
  sizeBytes: number;
  encryptedSizeBytes: number;
  blobUrl: string;
  blobDownloadUrl?: string;
  blobPathname: string;
  expiresInSeconds: number;
  expiryMode: "downloads" | "time";
  downloadLimit: number;
}) {
  const timestamp = nowSeconds();
  const sender = await requireActiveUser(input.roomId, input.senderId);
  const recipientIds = Array.from(new Set(input.recipients.map((recipient) => recipient.id)));

  if (recipientIds.length !== input.recipients.length) {
    throw new ApiError("Recipient list contains duplicates.");
  }

  const recipients = await Promise.all(recipientIds.map((id) => requireActiveUser(input.roomId, id)));
  if (recipients.some((recipient) => recipient.id === sender.id)) {
    throw new ApiError("Choose a recipient other than yourself.");
  }

  const shareId = randomId();
  const expiresAt = timestamp + input.expiresInSeconds;
  const ttl = secondsUntil(expiresAt) + SHARE_CLEANUP_GRACE_SECONDS;
  const clipIds = recipientIds.map(() => randomId());

  const share: ShareRecord = {
    id: shareId,
    roomId: input.roomId,
    senderId: sender.id,
    senderName: sender.username,
    recipientIds,
    clipIds,
    originalName: input.originalName,
    sizeBytes: input.sizeBytes,
    encryptedSizeBytes: input.encryptedSizeBytes,
    blobUrl: input.blobUrl,
    blobDownloadUrl: input.blobDownloadUrl,
    blobPathname: input.blobPathname,
    createdAt: timestamp,
    expiresAt,
    expiryMode: input.expiryMode,
    downloadLimit: input.downloadLimit
  };

  await kvSet(shareKey(shareId), share, ttl);
  await kvSet(shareViewsKey(shareId), input.downloadLimit, ttl);

  await Promise.all(
    input.recipients.map(async (recipient, index) => {
      const clip: ClipRecord = {
        id: clipIds[index],
        shareId,
        roomId: input.roomId,
        senderId: sender.id,
        senderName: sender.username,
        recipientId: recipient.id,
        originalName: input.originalName,
        sizeBytes: input.sizeBytes,
        metadata: recipient.metadata,
        createdAt: timestamp,
        expiresAt
      };
      await kvSet(clipKey(clip.id), clip, ttl);
      await setAdd(inboxKey(recipient.id), clip.id);
      await setExpire(inboxKey(recipient.id), ttl);
    })
  );

  return share;
}

export async function getViewsLeft(shareId: string) {
  return (await kvGet<number>(shareViewsKey(shareId))) ?? 0;
}

export async function listInbox(roomId: string, userId: string): Promise<InboxClip[]> {
  await requireActiveUser(roomId, userId);
  const ids = await setMembers(inboxKey(userId));
  const rows = await Promise.all(
    ids.map(async (id) => {
      const clip = await kvGet<ClipRecord>(clipKey(id));
      if (!clip || clip.roomId !== roomId || clip.recipientId !== userId) return null;
      const share = await kvGet<ShareRecord>(shareKey(clip.shareId));
      if (!share) return null;
      if (share.expiresAt <= nowSeconds()) {
        await cleanupShare(share);
        return null;
      }
      const viewsLeft = await getViewsLeft(share.id);
      if (viewsLeft <= 0) return null;
      return {
        id: clip.id,
        senderName: clip.senderName,
        filename: clip.originalName,
        sizeBytes: clip.sizeBytes,
        createdAt: clip.createdAt,
        expiresAt: clip.expiresAt,
        expiryMode: share.expiryMode,
        viewsLeft
      };
    })
  );

  return rows
    .filter((row): row is InboxClip => !!row)
    .sort((a, b) => b.createdAt - a.createdAt);
}

export async function claimDownload(clipId: string, userId: string) {
  const clip = await kvGet<ClipRecord>(clipKey(clipId));
  if (!clip || clip.recipientId !== userId) throw new ApiError("This file is no longer available.", 404);

  await requireActiveUser(clip.roomId, userId);
  const share = await kvGet<ShareRecord>(shareKey(clip.shareId));
  if (!share || share.expiresAt <= nowSeconds()) {
    if (share) await cleanupShare(share);
    throw new ApiError("This file is no longer available.", 404);
  }

  const remaining = await decrementIfPositive(shareViewsKey(share.id));
  if (remaining < 0) throw new ApiError("This file is no longer available.", 404);

  return { clip, share, remaining };
}

export async function cleanupShare(share: ShareRecord) {
  await Promise.allSettled([
    deleteBlob(share.blobUrl).catch(() => undefined),
    kvDel(shareKey(share.id), shareViewsKey(share.id), ...share.clipIds.map(clipKey)),
    ...share.recipientIds.map((recipientId) => setRemove(inboxKey(recipientId), ...share.clipIds))
  ]);
}

export function isDurableStoreConfigured() {
  return !!redis;
}
