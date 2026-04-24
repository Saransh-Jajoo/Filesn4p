(function () {
    "use strict";

    /* ============================================================
       CONSTANTS
       ============================================================ */
    const encoder = new TextEncoder();
    const MAX_FILE_SIZE = 20 * 1024 * 1024;
    const CURVE = "P-256";
    const CURVE_BITS = 256;
    const WRAP_INFO = encoder.encode("secure-vault-live-clipboard-v1");
    const PUBLIC_KEY_TYPE = "secure-vault-live-public-key";

    /* ============================================================
       STATE
       ============================================================ */
    const state = {
        roomId: null,
        userId: null,
        username: null,
        keyPair: null,
        publicKeyDoc: null,
        fingerprint: null,
        selectedFile: null,
        selectedRecipient: null,
        searchResults: [],
        timers: []
    };

    /* ============================================================
       CRYPTO HELPERS  (preserved from original — E2E encryption)
       ============================================================ */
    function subtleCrypto() {
        if (!window.crypto || !window.crypto.subtle) {
            throw new Error("Web Crypto is unavailable. Use localhost or HTTPS.");
        }
        return window.crypto.subtle;
    }

    function randomBytes(length) {
        const bytes = new Uint8Array(length);
        window.crypto.getRandomValues(bytes);
        return bytes;
    }

    function toBase64(buffer) {
        const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
        let binary = "";
        const chunk = 0x8000;
        for (let i = 0; i < bytes.length; i += chunk) {
            binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
        }
        return btoa(binary);
    }

    function fromBase64(value) {
        const binary = atob(String(value || "").replace(/\s/g, ""));
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return bytes;
    }

    function sanitizeName(name) {
        return String(name || "").replace(/[\\/:*?"<>|]/g, "_").replace(/\s+/g, " ").trim() || "shared-file";
    }

    function escapeText(value) {
        return String(value || "").replace(/[&<>"']/g, (c) => ({
            "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
        }[c]));
    }

    /* ============================================================
       IDENTITY & KEY EXCHANGE
       ============================================================ */
    async function generateIdentity() {
        const keyPair = await subtleCrypto().generateKey(
            { name: "ECDH", namedCurve: CURVE }, true, ["deriveBits"]
        );
        const spki = await subtleCrypto().exportKey("spki", keyPair.publicKey);
        const hash = new Uint8Array(await subtleCrypto().digest("SHA-256", spki));
        const fingerprint = Array.from(hash.slice(0, 8), (b) => b.toString(16).padStart(2, "0").toUpperCase())
            .join("").match(/.{1,4}/g).join("-");

        return {
            keyPair,
            fingerprint,
            publicKeyDoc: {
                type: PUBLIC_KEY_TYPE,
                version: 1,
                algorithm: "ECDH",
                curve: CURVE,
                publicKey: { format: "spki", data: toBase64(spki) }
            }
        };
    }

    async function importPublicKey(doc) {
        if (!doc || doc.type !== PUBLIC_KEY_TYPE || doc.curve !== CURVE) {
            throw new Error("Receiver public key is not supported.");
        }
        return subtleCrypto().importKey(
            "spki", fromBase64(doc.publicKey && doc.publicKey.data),
            { name: "ECDH", namedCurve: CURVE }, false, []
        );
    }

    async function deriveWrapKey(privateKey, publicKey, salt, usages) {
        const shared = await subtleCrypto().deriveBits(
            { name: "ECDH", public: publicKey }, privateKey, CURVE_BITS
        );
        const material = await subtleCrypto().importKey("raw", shared, "HKDF", false, ["deriveKey"]);
        return subtleCrypto().deriveKey(
            { name: "HKDF", hash: "SHA-256", salt, info: WRAP_INFO },
            material,
            { name: "AES-GCM", length: 256 }, false, usages
        );
    }

    /* ============================================================
       ENCRYPT / DECRYPT (E2E — automatic, no passwords)
       ============================================================ */
    async function encryptForRecipient(file, recipient) {
        const recipientPublic = await importPublicKey(recipient.public_key);
        const ephemeral = await subtleCrypto().generateKey(
            { name: "ECDH", namedCurve: CURVE }, true, ["deriveBits"]
        );
        const fileKey = await subtleCrypto().generateKey(
            { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
        );
        const fileNonce = randomBytes(12);
        const wrapSalt = randomBytes(16);
        const wrapNonce = randomBytes(12);
        const wrapKey = await deriveWrapKey(ephemeral.privateKey, recipientPublic, wrapSalt, ["encrypt"]);
        const rawFileKey = await subtleCrypto().exportKey("raw", fileKey);
        const wrappedKey = await subtleCrypto().encrypt(
            { name: "AES-GCM", iv: wrapNonce }, wrapKey, rawFileKey
        );
        const plaintext = await file.arrayBuffer();
        const ciphertext = await subtleCrypto().encrypt(
            { name: "AES-GCM", iv: fileNonce }, fileKey, plaintext
        );
        const ephPub = await subtleCrypto().exportKey("spki", ephemeral.publicKey);

        const metadata = {
            type: "secure-vault-live-clip",
            version: 1,
            algorithm: "ECDH-HKDF-SHA256-AES-256-GCM",
            curve: CURVE,
            filename: sanitizeName(file.name),
            sender: { username: state.username, fingerprint: state.fingerprint },
            recipient: { username: recipient.username, fingerprint: recipient.fingerprint },
            ephemeralPublicKey: { format: "spki", data: toBase64(ephPub) },
            kdf: { name: "HKDF", hash: "SHA-256", salt: toBase64(wrapSalt), info: toBase64(WRAP_INFO) },
            wrappedKey: { name: "AES-GCM", nonce: toBase64(wrapNonce), data: toBase64(wrappedKey) },
            cipher: { name: "AES-GCM", nonce: toBase64(fileNonce) }
        };

        return { metadata, ciphertext: new Blob([ciphertext], { type: "application/octet-stream" }) };
    }

    async function decryptClip(metadata, ciphertext) {
        if (!metadata || metadata.type !== "secure-vault-live-clip" || metadata.curve !== CURVE) {
            throw new Error("This encrypted clip is not supported.");
        }
        const senderPublic = await subtleCrypto().importKey(
            "spki", fromBase64(metadata.ephemeralPublicKey && metadata.ephemeralPublicKey.data),
            { name: "ECDH", namedCurve: CURVE }, false, []
        );
        const wrapKey = await deriveWrapKey(
            state.keyPair.privateKey, senderPublic,
            fromBase64(metadata.kdf && metadata.kdf.salt), ["decrypt"]
        );
        const rawFileKey = await subtleCrypto().decrypt(
            { name: "AES-GCM", iv: fromBase64(metadata.wrappedKey && metadata.wrappedKey.nonce) },
            wrapKey, fromBase64(metadata.wrappedKey && metadata.wrappedKey.data)
        );
        const fileKey = await subtleCrypto().importKey(
            "raw", rawFileKey, { name: "AES-GCM", length: 256 }, false, ["decrypt"]
        );
        return subtleCrypto().decrypt(
            { name: "AES-GCM", iv: fromBase64(metadata.cipher && metadata.cipher.nonce) },
            fileKey, ciphertext
        );
    }

    /* ============================================================
       API HELPERS
       ============================================================ */
    function csrfToken() {
        const meta = document.querySelector('meta[name="csrf-token"]');
        return meta ? meta.content : "";
    }

    async function apiFetch(url, options) {
        const opts = options || {};
        const headers = new Headers(opts.headers || {});
        headers.set("X-CSRFToken", csrfToken());
        if (opts.body && !(opts.body instanceof FormData) && !headers.has("Content-Type")) {
            headers.set("Content-Type", "application/json");
        }
        const response = await fetch(url, Object.assign({}, opts, { credentials: "same-origin", headers }));
        if (!response.ok) {
            let msg = "Request failed.";
            try { const d = await response.json(); msg = d.error || msg; } catch (_) { msg = response.statusText || msg; }
            throw new Error(msg);
        }
        return response;
    }

    function downloadBlob(data, filename, type) {
        const blob = data instanceof Blob ? data : new Blob([data], { type: type || "application/octet-stream" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = sanitizeName(filename);
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    /* ============================================================
       UI HELPERS
       ============================================================ */
    function $(id) { return document.getElementById(id); }

    function setStatus(el, msg, kind) {
        if (!el) return;
        el.textContent = msg || "";
        el.classList.remove("is-error", "is-success");
        if (kind) el.classList.add("is-" + kind);
    }

    function showPage(id) {
        document.querySelectorAll(".page").forEach((p) => p.classList.remove("active"));
        const page = $(id);
        if (page) page.classList.add("active");
    }

    function showTab(name) {
        document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
        document.querySelectorAll(".nav-tab").forEach((btn) => {
            btn.classList.toggle("active", btn.dataset.tab === name);
        });
        const tab = $("tab-" + name);
        if (tab) tab.classList.add("active");
    }

    function showStep(id) {
        document.querySelectorAll("#tab-send .step").forEach((s) => s.classList.remove("active"));
        const step = $(id);
        if (step) step.classList.add("active");
    }

    function formatBytes(size) {
        if (size < 1024) return size + " B";
        if (size < 1024 * 1024) return (size / 1024).toFixed(1) + " KB";
        return (size / (1024 * 1024)).toFixed(1) + " MB";
    }

    function formatExpiry(timestamp) {
        const rem = Math.max(0, timestamp - Math.floor(Date.now() / 1000));
        if (rem < 60) return rem + "s";
        if (rem < 3600) return Math.ceil(rem / 60) + "m";
        return Math.ceil(rem / 3600) + "h";
    }

    /* ============================================================
       LOGIN
       ============================================================ */
    async function doLogin(event) {
        event.preventDefault();
        const form = event.currentTarget;
        const status = $("login-status");
        const username = form.elements.username.value.trim();
        const btn = $("login-btn");

        try {
            btn.disabled = true;
            setStatus(status, "Generating encryption keys...");

            const identity = await generateIdentity();
            const res = await apiFetch("/api/rooms", {
                method: "POST",
                body: JSON.stringify({
                    username,
                    public_key: identity.publicKeyDoc,
                    fingerprint: identity.fingerprint
                })
            });
            const data = await res.json();

            state.roomId = data.room_id;
            state.userId = data.user_id;
            state.username = data.username;
            state.keyPair = identity.keyPair;
            state.publicKeyDoc = identity.publicKeyDoc;
            state.fingerprint = identity.fingerprint;

            $("nav-username").textContent = state.username;
            $("nav-fingerprint").textContent = state.fingerprint;
            showPage("page-app");
            startPolling();
        } catch (err) {
            setStatus(status, err.message, "error");
        } finally {
            btn.disabled = false;
        }
    }

    /* ============================================================
       FILE SELECTION
       ============================================================ */
    function setupUploadZone() {
        const zone = $("upload-zone");
        const input = $("file-input");
        const preview = $("file-preview");
        const nameEl = $("file-name");
        const sizeEl = $("file-size");
        const removeBtn = $("file-remove");
        const nextBtn = $("btn-next");

        zone.addEventListener("click", () => input.click());
        zone.addEventListener("dragover", (e) => { e.preventDefault(); zone.classList.add("drag-over"); });
        zone.addEventListener("dragleave", () => zone.classList.remove("drag-over"));
        zone.addEventListener("drop", (e) => {
            e.preventDefault();
            zone.classList.remove("drag-over");
            if (e.dataTransfer.files.length) {
                selectFile(e.dataTransfer.files[0]);
            }
        });

        input.addEventListener("change", () => {
            if (input.files[0]) selectFile(input.files[0]);
        });

        removeBtn.addEventListener("click", () => {
            state.selectedFile = null;
            input.value = "";
            preview.hidden = true;
            zone.hidden = false;
            nextBtn.disabled = true;
        });

        function selectFile(file) {
            if (file.size > MAX_FILE_SIZE) {
                alert("File is too large. Maximum size is 20 MB.");
                return;
            }
            state.selectedFile = file;
            nameEl.textContent = file.name;
            sizeEl.textContent = formatBytes(file.size);
            preview.hidden = false;
            zone.hidden = true;
            nextBtn.disabled = false;
        }
    }

    /* ============================================================
       EXPIRY MODE TOGGLE
       ============================================================ */
    function setupExpiryToggle() {
        const radios = document.querySelectorAll('input[name="expiry_mode"]');
        const downloadsDiv = $("expiry-downloads");
        const timeDiv = $("expiry-time");

        radios.forEach((radio) => {
            radio.addEventListener("change", () => {
                if (radio.value === "downloads") {
                    downloadsDiv.hidden = false;
                    timeDiv.hidden = true;
                } else {
                    downloadsDiv.hidden = true;
                    timeDiv.hidden = false;
                }
            });
        });
    }

    /* ============================================================
       STEP NAVIGATION
       ============================================================ */
    function setupStepNav() {
        $("btn-next").addEventListener("click", () => {
            if (!state.selectedFile) return;
            showStep("step-recipient");
        });

        $("btn-back").addEventListener("click", () => {
            showStep("step-upload");
        });

        $("btn-send-another").addEventListener("click", () => {
            // Reset state for next send
            state.selectedFile = null;
            state.selectedRecipient = null;
            $("file-input").value = "";
            $("file-preview").hidden = true;
            $("upload-zone").hidden = false;
            $("btn-next").disabled = true;
            $("search-input").value = "";
            $("search-results").innerHTML = '<p class="hint">Type a username and click Search.</p>';
            $("btn-send").disabled = true;
            setStatus($("send-status"), "");
            showStep("step-upload");
        });
    }

    /* ============================================================
       TAB NAVIGATION
       ============================================================ */
    function setupTabs() {
        document.querySelectorAll(".nav-tab").forEach((btn) => {
            btn.addEventListener("click", () => {
                showTab(btn.dataset.tab);
                if (btn.dataset.tab === "inbox") refreshInbox();
            });
        });
    }

    /* ============================================================
       SEARCH USERS
       ============================================================ */
    function setupSearch() {
        const input = $("search-input");
        const btn = $("search-btn");
        const results = $("search-results");

        async function doSearch() {
            const query = input.value.trim();
            if (!query) {
                results.innerHTML = '<p class="hint">Type a username and click Search.</p>';
                return;
            }

            btn.disabled = true;
            results.innerHTML = '<p class="hint">Searching...</p>';

            try {
                const res = await apiFetch(
                    `/api/rooms/${state.roomId}/users/search?q=${encodeURIComponent(query)}&user_id=${encodeURIComponent(state.userId)}`
                );
                const data = await res.json();
                state.searchResults = data.users || [];
                state.selectedRecipient = null;
                $("btn-send").disabled = true;
                renderSearchResults();
            } catch (err) {
                results.innerHTML = `<p class="hint">${escapeText(err.message)}</p>`;
            } finally {
                btn.disabled = false;
            }
        }

        btn.addEventListener("click", doSearch);
        input.addEventListener("keydown", (e) => {
            if (e.key === "Enter") { e.preventDefault(); doSearch(); }
        });
    }

    function renderSearchResults() {
        const container = $("search-results");
        const users = state.searchResults;

        if (!users.length) {
            container.innerHTML = '<p class="hint">No users found. Make sure they are online.</p>';
            return;
        }

        container.innerHTML = users.map((u) => `
            <div class="search-result" data-user-id="${escapeText(u.id)}">
                <div class="user-avatar">${escapeText(u.username.charAt(0).toUpperCase())}</div>
                <div class="user-details">
                    <div class="user-name">${escapeText(u.username)}</div>
                    <div class="user-fp">${escapeText(u.fingerprint)}</div>
                </div>
                <div class="check-icon"></div>
            </div>
        `).join("");

        container.querySelectorAll(".search-result").forEach((card) => {
            card.addEventListener("click", () => {
                // Deselect all, select this one
                container.querySelectorAll(".search-result").forEach((c) => c.classList.remove("selected"));
                card.classList.add("selected");
                const userId = card.dataset.userId;
                state.selectedRecipient = users.find((u) => u.id === userId) || null;
                $("btn-send").disabled = !state.selectedRecipient;
            });
        });
    }

    /* ============================================================
       SEND FILE
       ============================================================ */
    function setupSend() {
        $("btn-send").addEventListener("click", async () => {
            const status = $("send-status");
            const btn = $("btn-send");
            const file = state.selectedFile;
            const recipient = state.selectedRecipient;

            if (!file || !recipient || !state.keyPair) return;

            try {
                btn.disabled = true;
                setStatus(status, "Encrypting file...");

                const encrypted = await encryptForRecipient(file, recipient);
                const body = new FormData();
                body.append("sender_id", state.userId);
                body.append("recipient_id", recipient.id);

                // Expiry mode
                const mode = document.querySelector('input[name="expiry_mode"]:checked').value;
                body.append("expiry_mode", mode);
                if (mode === "downloads") {
                    body.append("view_limit", $("view-limit").value);
                } else {
                    body.append("expires_in", $("expire-time").value);
                }

                body.append("metadata", JSON.stringify(encrypted.metadata));
                body.append("payload", encrypted.ciphertext, sanitizeName(file.name) + ".clip");

                setStatus(status, "Uploading encrypted file...");
                await apiFetch(`/api/rooms/${state.roomId}/clips`, { method: "POST", body });

                showStep("step-sent");
            } catch (err) {
                setStatus(status, err.message, "error");
            } finally {
                btn.disabled = false;
            }
        });
    }

    /* ============================================================
       INBOX
       ============================================================ */
    async function refreshInbox() {
        if (!state.roomId || !state.userId) return;

        try {
            const res = await apiFetch(
                `/api/rooms/${state.roomId}/clips?user_id=${encodeURIComponent(state.userId)}`
            );
            const data = await res.json();
            const clips = data.clips || [];
            renderInbox(clips);

            // Update badge
            const badge = $("inbox-badge");
            if (clips.length > 0) {
                badge.textContent = clips.length;
                badge.hidden = false;
            } else {
                badge.hidden = true;
            }
        } catch (_) {
            // Silent fail on poll
        }
    }

    function renderInbox(clips) {
        const list = $("inbox-list");
        if (!list) return;

        if (!clips.length) {
            list.innerHTML = '<p class="hint">No incoming files yet.</p>';
            return;
        }

        list.innerHTML = clips.map((c) => `
            <div class="inbox-item">
                <div class="inbox-meta">
                    <strong>${escapeText(c.filename)}</strong>
                    <span>From ${escapeText(c.sender_name)} · ${formatBytes(c.size_bytes)} · ${c.views_left > 9000 ? "expires in " + formatExpiry(c.expires_at) : c.views_left + " download" + (c.views_left === 1 ? "" : "s") + " left"}</span>
                </div>
                <button type="button" class="btn-open" data-clip-id="${escapeText(c.id)}">Open</button>
            </div>
        `).join("");

        list.querySelectorAll("[data-clip-id]").forEach((btn) => {
            btn.addEventListener("click", () => openClip(btn.dataset.clipId));
        });
    }

    async function openClip(clipId) {
        const status = $("inbox-status");
        try {
            setStatus(status, "Downloading encrypted file...");
            const res = await apiFetch(
                `/api/clips/${clipId}/download?user_id=${encodeURIComponent(state.userId)}`
            );
            const metadata = JSON.parse(res.headers.get("X-Clip-Metadata") || "{}");
            const encrypted = await res.arrayBuffer();

            setStatus(status, "Decrypting in your browser...");
            const plain = await decryptClip(metadata, encrypted);
            downloadBlob(plain, metadata.filename || "shared-file");
            setStatus(status, "File decrypted and downloaded.", "success");
            await refreshInbox();
        } catch (err) {
            setStatus(status, err.message, "error");
            await refreshInbox();
        }
    }

    /* ============================================================
       HEARTBEAT & POLLING
       ============================================================ */
    async function heartbeat() {
        if (!state.roomId || !state.userId) return;
        await apiFetch(`/api/rooms/${state.roomId}/heartbeat`, {
            method: "POST",
            body: JSON.stringify({ user_id: state.userId })
        });
    }

    function startPolling() {
        state.timers.forEach((t) => clearInterval(t));
        state.timers = [
            setInterval(() => heartbeat().catch(() => {}), 15000),
            setInterval(() => refreshInbox().catch(() => {}), 5000)
        ];
        refreshInbox();
    }

    /* ============================================================
       INITIALISE
       ============================================================ */
    function init() {
        // Login
        const loginForm = $("login-form");
        if (loginForm) loginForm.addEventListener("submit", doLogin);

        // Upload zone
        setupUploadZone();
        setupExpiryToggle();
        setupStepNav();
        setupTabs();
        setupSearch();
        setupSend();

        // Web Crypto check
        if (!window.crypto || !window.crypto.subtle) {
            setStatus($("login-status"), "Web Crypto is unavailable. Use localhost or HTTPS.", "error");
        }
    }

    init();
}());
