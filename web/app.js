(() => {
  "use strict";

  const state = {
    session: null,
    maxUpload: null,
    path: "",
    listing: null,
    requestSeq: 0,
    filter: "",
    loading: false,
    emptyAction: null,
    toastTimer: null,
    uploadChain: Promise.resolve(),
    uploadsActive: 0,
    previewAbort: null,
    previewToken: 0,
    previewList: [],
    previewIndex: -1,
    sort: { key: "name", direction: 1 },
    quickEntries: [],
    quickPaths: new Set(),
    deviceKey: null,
    pubkeyAttempt: null,
  };

  const TEXT_PREVIEW_LIMIT = 1024 * 1024;
  const el = {};
  const dateFormatter = new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
  const integerFormatter = new Intl.NumberFormat();

  class ApiError extends Error {
    constructor(status, message) {
      super(message);
      this.name = "ApiError";
      this.status = status;
    }
  }

  function byId(id) {
    const node = document.getElementById(id);
    if (!node) {
      throw new Error(`Missing element #${id}`);
    }
    return node;
  }

  function cacheElements() {
    Object.assign(el, {
      boot: byId("boot"),
      loginView: byId("login-view"),
      loginForm: byId("login-form"),
      loginUsername: byId("login-username"),
      loginPassword: byId("login-password"),
      loginError: byId("login-error"),
      loginSubmit: byId("login-submit"),
      app: byId("app"),
      userName: byId("user-name"),
      logoutButton: byId("logout-button"),
      keysButton: byId("keys-button"),
      refreshButton: byId("refresh-button"),
      newFolderButton: byId("new-folder-button"),
      uploadButton: byId("upload-button"),
      breadcrumb: byId("breadcrumb"),
      dirTitle: byId("dir-title"),
      dirSubtitle: byId("dir-subtitle"),
      statFolders: byId("stat-folders"),
      statFiles: byId("stat-files"),
      statSize: byId("stat-size"),
      statFree: byId("stat-free"),
      dropzone: byId("dropzone"),
      fileInput: byId("file-input"),
      dropHint: byId("drop-hint"),
      browseButton: byId("browse-button"),
      uploadPanel: byId("upload-panel"),
      uploadSummary: byId("upload-summary"),
      uploadList: byId("upload-list"),
      clearUploadsButton: byId("clear-uploads-button"),
      browserCard: byId("browser-card"),
      browserStatus: byId("browser-status"),
      filterInput: byId("filter-input"),
      tableWrap: byId("table-wrap"),
      fileList: byId("file-list"),
      emptyState: byId("empty-state"),
      emptyTitle: byId("empty-title"),
      emptyCopy: byId("empty-copy"),
      emptyAction: byId("empty-action"),
      versionLabel: byId("version-label"),
      securityLabel: byId("security-label"),
      mkdirDialog: byId("mkdir-dialog"),
      mkdirForm: byId("mkdir-form"),
      mkdirName: byId("mkdir-name"),
      mkdirError: byId("mkdir-error"),
      mkdirSubmit: byId("mkdir-submit"),
      mkdirClose: byId("mkdir-close"),
      mkdirCancel: byId("mkdir-cancel"),
      keysDialog: byId("keys-dialog"),
      keysClose: byId("keys-close"),
      keysDone: byId("keys-done"),
      keysEnable: byId("keys-enable"),
      keysStatus: byId("keys-status"),
      keysList: byId("keys-list"),
      keysEmpty: byId("keys-empty"),
      previewDialog: byId("preview-dialog"),
      previewTitle: byId("preview-title"),
      previewBody: byId("preview-body"),
      previewDownload: byId("preview-download"),
      previewClose: byId("preview-close"),
      previewPrev: byId("preview-prev"),
      previewNext: byId("preview-next"),
      previewCount: byId("preview-count"),
      previewNav: byId("preview-nav"),
      previewFooter: byId("preview-footer"),
      previewNote: byId("preview-note"),
      quickList: byId("quick-list"),
      quickCount: byId("quick-count"),
      quickEmpty: byId("quick-empty"),
      toast: byId("toast"),
    });
  }

  function makeIcon(name, className = "icon") {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("class", className);
    svg.setAttribute("aria-hidden", "true");
    const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    use.setAttribute("href", `#i-${name}`);
    svg.appendChild(use);
    return svg;
  }

  async function api(path, options = {}) {
    const method = (options.method || "GET").toUpperCase();
    const headers = new Headers(options.headers || {});
    const init = { ...options, method, headers, credentials: "same-origin" };
    delete init.json;
    if (method !== "GET" && method !== "HEAD") {
      headers.set("X-LanVault-Request", "1");
    }
    if (options.json !== undefined) {
      headers.set("Content-Type", "application/json");
      init.body = JSON.stringify(options.json);
    }

    let response;
    try {
      response = await fetch(path, init);
    } catch (error) {
      throw new ApiError(0, "Cannot reach the server.");
    }

    let data = null;
    const contentType = response.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
      try {
        data = await response.json();
      } catch (error) {
        data = null;
      }
    }

    if (!response.ok) {
      if (response.status === 401 && state.session) {
        handleSessionLost();
      }
      const message = data && data.error ? data.error : `Request failed (${response.status}).`;
      throw new ApiError(response.status, message);
    }
    return data;
  }

  // --- Passwordless sign-in: WebCrypto challenge-response with a stored key ---

  const KEY_DB_NAME = "lanvault-auth";
  const KEY_STORE_NAME = "device-key";
  const DEVICE_KEY_ID = "current";

  function bytesToBase64(bytes) {
    let binary = "";
    for (let i = 0; i < bytes.length; i += 0x8000) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(binary);
  }

  function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i += 1) {
      bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  function bytesToHex(bytes) {
    return Array.from(bytes)
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
  }

  function openKeyDb() {
    return new Promise((resolve, reject) => {
      if (!window.indexedDB) {
        reject(new Error("IndexedDB is unavailable."));
        return;
      }
      const request = indexedDB.open(KEY_DB_NAME, 1);
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(KEY_STORE_NAME)) {
          db.createObjectStore(KEY_STORE_NAME);
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error || new Error("Cannot open the key store."));
      request.onblocked = () => reject(new Error("The key store is blocked."));
    });
  }

  function idbGet(key) {
    return openKeyDb().then(
      (db) =>
        new Promise((resolve, reject) => {
          const request = db
            .transaction(KEY_STORE_NAME, "readonly")
            .objectStore(KEY_STORE_NAME)
            .get(key);
          request.onsuccess = () => {
            db.close();
            resolve(request.result || null);
          };
          request.onerror = () => {
            db.close();
            reject(request.error);
          };
        })
    );
  }

  function idbSet(key, value) {
    return openKeyDb().then(
      (db) =>
        new Promise((resolve, reject) => {
          const transaction = db.transaction(KEY_STORE_NAME, "readwrite");
          const request = transaction.objectStore(KEY_STORE_NAME).put(value, key);
          request.onsuccess = () => resolve();
          request.onerror = () => reject(request.error);
          transaction.onabort = () =>
            reject(request.error || new Error("The key store write was aborted."));
          transaction.oncomplete = () => db.close();
        })
    );
  }

  async function loadDeviceKey() {
    if (state.deviceKey) {
      return state.deviceKey;
    }
    try {
      const record = await idbGet(DEVICE_KEY_ID);
      if (record && record.privateKey && record.publicKey) {
        state.deviceKey = record;
        return record;
      }
    } catch (error) {
      // No usable stored key; fall back to password sign-in.
    }
    return null;
  }

  async function ensureDeviceKey() {
    const existing = await loadDeviceKey();
    if (existing) {
      return existing;
    }
    if (!window.crypto || !crypto.subtle) {
      return null;
    }
    const pair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign", "verify"]
    );
    const record = {
      privateKey: pair.privateKey,
      publicKey: pair.publicKey,
      createdAt: Date.now(),
    };
    state.deviceKey = record;
    try {
      await idbSet(DEVICE_KEY_ID, record);
    } catch (error) {
      // Private browsing: keep the key for this session only.
    }
    return record;
  }

  async function devicePublicKeyPem(record) {
    const spki = await crypto.subtle.exportKey("spki", record.publicKey);
    const base64 = bytesToBase64(new Uint8Array(spki));
    const lines = [];
    for (let i = 0; i < base64.length; i += 64) {
      lines.push(base64.slice(i, i + 64));
    }
    return `-----BEGIN PUBLIC KEY-----\n${lines.join("\n")}\n-----END PUBLIC KEY-----`;
  }

  async function pemFingerprint(pem) {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(pem));
    return bytesToHex(new Uint8Array(digest));
  }

  async function attemptPublicKeyLogin() {
    if (state.pubkeyAttempt) {
      return state.pubkeyAttempt;
    }
    state.pubkeyAttempt = (async () => {
      try {
        const record = await loadDeviceKey();
        if (!record) {
          return null;
        }
        const challenge = await api("/api/auth/challenge", { method: "POST", json: {} });
        const nonce = hexToBytes(challenge.nonce);
        const signature = await crypto.subtle.sign(
          { name: "ECDSA", hash: "SHA-256" },
          record.privateKey,
          nonce
        );
        await api("/api/auth/verify", {
          method: "POST",
          json: {
            id: challenge.id,
            signature: bytesToBase64(new Uint8Array(signature)),
          },
        });
        return await api("/api/session");
      } catch (error) {
        return null;
      } finally {
        state.pubkeyAttempt = null;
      }
    })();
    return state.pubkeyAttempt;
  }

  async function registerDeviceKey() {
    if (!state.session || !state.session.publicKeyAuth) {
      return null;
    }
    try {
      const record = await ensureDeviceKey();
      if (!record) {
        return null;
      }
      const pem = await devicePublicKeyPem(record);
      return await api("/api/auth/keys", {
        method: "POST",
        json: { publicKey: pem },
      });
    } catch (error) {
      return null;
    }
  }

  function formatBytes(bytes) {
    if (!Number.isFinite(bytes) || bytes < 0) {
      return "-";
    }
    if (bytes < 1024) {
      return `${integerFormatter.format(bytes)} B`;
    }
    const units = ["KB", "MB", "GB", "TB", "PB"];
    let value = bytes / 1024;
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
      value /= 1024;
      unit += 1;
    }
    const digits = value >= 100 ? 0 : value >= 10 ? 1 : 2;
    return `${value.toLocaleString(undefined, { maximumFractionDigits: digits })} ${units[unit]}`;
  }

  function formatDate(epoch) {
    if (!Number.isFinite(epoch) || epoch <= 0) {
      return "-";
    }
    const date = new Date(epoch * 1000);
    if (Number.isNaN(date.getTime())) {
      return "-";
    }
    return dateFormatter.format(date);
  }

  function displayPath(path) {
    return path ? `/${path}` : "/";
  }

  function downloadUrl(path) {
    return `/api/download?path=${encodeURIComponent(path)}`;
  }

  function previewUrl(path) {
    return `/api/preview?path=${encodeURIComponent(path)}`;
  }

  function pathFromLocation() {
    return new URLSearchParams(window.location.search).get("path") || "";
  }

  function urlForPath(path) {
    const url = new URL("/", window.location.origin);
    if (path) {
      url.searchParams.set("path", path);
    }
    return `${url.pathname}${url.search}`;
  }

  function plural(count, singular, pluralForm) {
    return count === 1 ? singular : pluralForm;
  }

  function setLoginError(message) {
    if (!message) {
      el.loginError.textContent = "";
      el.loginError.hidden = true;
      return;
    }
    el.loginError.textContent = message;
    el.loginError.hidden = false;
  }

  function setLoginBusy(busy) {
    el.loginSubmit.disabled = busy;
    el.loginSubmit.classList.toggle("is-busy", busy);
  }

  function toast(message, kind = "info") {
    window.clearTimeout(state.toastTimer);
    el.toast.textContent = message;
    el.toast.dataset.kind = kind;
    el.toast.hidden = false;
    state.toastTimer = window.setTimeout(() => {
      el.toast.hidden = true;
    }, 5200);
  }

  function showLogin(message = "") {
    state.session = null;
    state.maxUpload = null;
    state.listing = null;
    state.path = "";
    state.filter = "";
    state.quickEntries = [];
    state.quickPaths = new Set();
    state.requestSeq += 1;
    state.loading = false;
    if (el.mkdirDialog && el.mkdirDialog.open) {
      el.mkdirDialog.close();
    }
    if (el.keysDialog && el.keysDialog.open) {
      el.keysDialog.close();
    }
    if (el.previewDialog && el.previewDialog.open) {
      el.previewDialog.close();
    }
    el.app.hidden = true;
    el.loginView.hidden = false;
    el.boot.hidden = true;
    el.filterInput.value = "";
    document.title = "LanVault";
    setLoginError(message);
    setLoginBusy(false);
    window.setTimeout(() => {
      if (el.loginUsername.value) {
        el.loginPassword.focus();
      } else {
        el.loginUsername.focus();
      }
    }, 20);
  }

  function enterApp(session) {
    state.session = session;
    state.maxUpload = session.maxUpload || null;
    el.userName.textContent = session.user;
    el.versionLabel.textContent = `v${session.version}`;
    el.securityLabel.textContent = session.secure ? "TLS encrypted" : "HTTP - unencrypted";
    el.securityLabel.title = session.secure
      ? "Traffic between this browser and the server is encrypted."
      : "Traffic between this browser and the server is not encrypted.";
    el.loginView.hidden = true;
    el.app.hidden = false;
    el.boot.hidden = true;
    setLoginError("");
  }

  async function startApp(session) {
    enterApp(session);
    renderQuickAccess();
    loadQuickAccess();
    const initialPath = pathFromLocation();
    const ok = await navigate(initialPath, { push: false });
    if (!ok && initialPath && state.session) {
      toast("That folder was not found. Opened the root folder.", "error");
      await navigate("", { push: false });
    }
  }

  async function handleLogin(event) {
    event.preventDefault();
    const username = el.loginUsername.value;
    const password = el.loginPassword.value;
    if (!username || !password) {
      setLoginError("Enter a username and password.");
      return;
    }
    setLoginError("");
    setLoginBusy(true);
    try {
      await api("/api/login", {
        method: "POST",
        json: { username, password },
      });
      const session = await api("/api/session");
      el.loginForm.reset();
      await startApp(session);
      registerDeviceKey().then((result) => {
        if (result && result.created) {
          toast("This browser can now sign in without a password.");
        }
      });
    } catch (error) {
      if (error.status === 0) {
        setLoginError(error.message);
      } else if (error.status === 401) {
        setLoginError("Invalid username or password.");
      } else {
        setLoginError(error.message);
      }
      el.loginPassword.focus();
      el.loginPassword.select();
    } finally {
      setLoginBusy(false);
    }
  }

  async function handleLogout() {
    if (state.uploadsActive > 0 && !window.confirm("Uploads are still running. Sign out anyway?")) {
      return;
    }
    el.logoutButton.disabled = true;
    try {
      await api("/api/logout", { method: "POST" });
    } catch (error) {
      if (error.status !== 401) {
        toast(error.message, "error");
        el.logoutButton.disabled = false;
        return;
      }
    }
    el.logoutButton.disabled = false;
    el.loginForm.reset();
    state.uploadChain = Promise.resolve();
    state.uploadsActive = 0;
    el.uploadList.replaceChildren();
    el.uploadPanel.hidden = true;
    el.uploadSummary.textContent = "Waiting to upload.";
    window.history.replaceState(null, "", "/");
    showLogin();
    toast("Signed out.");
  }

  function handleSessionLost() {
    showLogin("Your session expired. Sign in again.");
    attemptPublicKeyLogin().then((session) => {
      if (session && !state.session) {
        startApp(session);
        toast("Signed in with this browser's key.");
      }
    });
  }

  async function openKeysDialog() {
    if (!state.session) {
      return;
    }
    el.keysDialog.showModal();
    await refreshKeysDialog();
  }

  function closeKeysDialog() {
    if (el.keysDialog.open) {
      el.keysDialog.close();
    }
  }

  async function refreshKeysDialog() {
    if (!state.session) {
      return;
    }
    if (!state.session.publicKeyAuth) {
      el.keysStatus.textContent =
        "Passwordless sign-in is unavailable: the server is missing the openssl tool.";
      el.keysEnable.hidden = true;
      el.keysList.replaceChildren();
      el.keysEmpty.hidden = true;
      return;
    }
    if (!window.crypto || !crypto.subtle) {
      el.keysStatus.textContent =
        "Passwordless sign-in needs a secure context. Use HTTPS, or open this page on the server itself.";
      el.keysEnable.hidden = true;
      el.keysList.replaceChildren();
      el.keysEmpty.hidden = true;
      return;
    }
    let localFingerprint = null;
    try {
      const record = await loadDeviceKey();
      if (record) {
        localFingerprint = await pemFingerprint(await devicePublicKeyPem(record));
      }
    } catch (error) {
      localFingerprint = null;
    }
    let keys = [];
    try {
      const data = await api("/api/auth/keys");
      keys = Array.isArray(data.keys) ? data.keys : [];
    } catch (error) {
      el.keysStatus.textContent = error.message;
      el.keysEnable.hidden = true;
      el.keysList.replaceChildren();
      el.keysEmpty.hidden = true;
      return;
    }
    const registered = Boolean(
      localFingerprint && keys.some((key) => key.fingerprint === localFingerprint)
    );
    el.keysEnable.hidden = registered;
    el.keysStatus.textContent = registered
      ? "This browser signs in without a password."
      : "This browser is not registered yet.";
    el.keysEmpty.hidden = keys.length > 0;
    el.keysList.replaceChildren();
    for (const key of keys) {
      const item = document.createElement("li");
      item.className =
        key.fingerprint === localFingerprint ? "keys-item is-local" : "keys-item";

      const body = document.createElement("div");
      body.className = "keys-item-body";
      const label = document.createElement("span");
      label.className = "keys-item-label";
      label.textContent = key.label || "Unknown device";
      const meta = document.createElement("span");
      meta.className = "keys-item-meta";
      const created = key.createdAt
        ? dateFormatter.format(new Date(key.createdAt * 1000))
        : "";
      meta.textContent = created
        ? `${created} · ${String(key.fingerprint).slice(0, 12)}`
        : String(key.fingerprint).slice(0, 12);
      body.append(label, meta);

      const actions = document.createElement("div");
      actions.className = "keys-item-actions";
      if (key.fingerprint === localFingerprint) {
        const badge = document.createElement("span");
        badge.className = "keys-badge";
        badge.textContent = "This browser";
        actions.append(badge);
      }
      const remove = document.createElement("button");
      remove.className = "text-button";
      remove.type = "button";
      remove.textContent = "Remove";
      remove.addEventListener("click", () => removeSignInKey(key));
      actions.append(remove);

      item.append(body, actions);
      el.keysList.append(item);
    }
  }

  async function removeSignInKey(key) {
    const label = key.label || "this key";
    if (!window.confirm(`Remove the sign-in key for ${label}?`)) {
      return;
    }
    try {
      await api("/api/auth/keys/remove", { method: "POST", json: { id: key.id } });
      toast("Sign-in key removed.");
      await refreshKeysDialog();
    } catch (error) {
      toast(error.message, "error");
    }
  }

  async function enableCurrentBrowser() {
    el.keysEnable.disabled = true;
    try {
      const result = await registerDeviceKey();
      if (result) {
        toast("This browser can now sign in without a password.");
        await refreshKeysDialog();
      } else {
        toast("Cannot register this browser.", "error");
      }
    } finally {
      el.keysEnable.disabled = false;
    }
  }

  function setLoadingUi(loading) {
    state.loading = loading;
    el.browserCard.classList.toggle("is-loading", loading);
    if (loading) {
      el.browserStatus.textContent = "Loading folder...";
    }
    updateUploadAvailability();
  }

  async function navigate(path, { push = false, resetFilter = true } = {}) {
    if (!state.session) {
      return false;
    }
    const seq = ++state.requestSeq;
    if (resetFilter) {
      state.filter = "";
      el.filterInput.value = "";
    }
    setLoadingUi(true);
    try {
      const query = new URLSearchParams({ path });
      const data = await api(`/api/list?${query.toString()}`);
      if (seq !== state.requestSeq || !state.session) {
        return false;
      }
      state.path = data.path;
      state.listing = data;
      state.loading = false;
      el.browserCard.classList.remove("is-loading");
      renderListing();
      updateUploadAvailability();
      const url = urlForPath(data.path);
      if (push) {
        window.history.pushState({ path: data.path }, "", url);
      } else {
        window.history.replaceState({ path: data.path }, "", url);
      }
      return true;
    } catch (error) {
      if (seq !== state.requestSeq) {
        return false;
      }
      state.loading = false;
      el.browserCard.classList.remove("is-loading");
      if (error.status === 401) {
        return false;
      }
      if (state.listing) {
        applyFilter();
      }
      showListFailure(error);
      return false;
    }
  }

  function showListFailure(error) {
    if (state.listing) {
      toast(`Could not open that folder: ${error.message}`, "error");
      updateBrowserStatus();
      updateUploadAvailability();
      return;
    }
    state.path = "";
    el.fileList.replaceChildren();
    el.tableWrap.hidden = true;
    el.emptyState.hidden = false;
    el.emptyState.querySelector("use").setAttribute("href", "#i-alert");
    el.emptyTitle.textContent = "Could not open this folder";
    el.emptyCopy.textContent = error.message;
    el.emptyAction.hidden = false;
    el.emptyAction.textContent = "Try the root folder";
    state.emptyAction = () => navigate("", { push: false });
    el.browserStatus.textContent = "Folder unavailable.";
    el.dirTitle.textContent = "Files";
    el.dirSubtitle.textContent = "The shared folder could not be loaded.";
    el.breadcrumb.replaceChildren();
    document.title = "LanVault";
    el.statFolders.textContent = "-";
    el.statFiles.textContent = "-";
    el.statSize.textContent = "-";
    el.statFree.textContent = "-";
    el.filterInput.disabled = true;
    updateUploadAvailability();
  }

  function renderListing() {
    const data = state.listing;
    if (!data) {
      return;
    }
    const segments = data.path ? data.path.split("/") : [];
    const title = segments.length ? segments[segments.length - 1] : data.rootName;
    el.dirTitle.textContent = title;
    el.dirSubtitle.textContent = data.path
      ? `Browsing a folder inside ${data.rootName}.`
      : `Everything shared from ${data.rootName}.`;
    document.title = `${title} - LanVault`;
    el.emptyAction.hidden = true;
    state.emptyAction = null;
    el.emptyState.querySelector("use").setAttribute("href", "#i-folder");
    renderBreadcrumb();
    renderStats();
    updateSortHeaders();
    renderTable();
    el.filterInput.disabled = false;
    updateUploadAvailability();
    updateBrowserStatus();
  }

  function renderBreadcrumb() {
    const data = state.listing;
    const segments = data.path ? data.path.split("/") : [];
    const fragment = document.createDocumentFragment();

    const addItem = (label, target, current) => {
      const li = document.createElement("li");
      if (current) {
        const span = document.createElement("span");
        span.className = "breadcrumb-current";
        span.textContent = label;
        span.setAttribute("aria-current", "page");
        span.title = label;
        li.appendChild(span);
      } else {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "breadcrumb-button";
        button.textContent = label;
        button.title = label;
        button.addEventListener("click", () => {
          navigate(target, { push: true });
        });
        li.appendChild(button);
      }
      fragment.appendChild(li);
    };

    addItem(data.rootName, "", segments.length === 0);
    segments.forEach((segment, index) => {
      const separatorLi = document.createElement("li");
      separatorLi.appendChild(makeIcon("chevron", "icon breadcrumb-separator"));
      separatorLi.setAttribute("aria-hidden", "true");
      fragment.appendChild(separatorLi);
      addItem(
        segment,
        segments.slice(0, index + 1).join("/"),
        index === segments.length - 1,
      );
    });
    el.breadcrumb.replaceChildren(fragment);
  }

  function renderStats() {
    const data = state.listing;
    const entries = data.entries;
    const folderCount = entries.filter((entry) => entry.isDir).length;
    const fileCount = entries.length - folderCount;
    el.statFolders.textContent = integerFormatter.format(folderCount);
    el.statFiles.textContent = integerFormatter.format(fileCount);
    el.statSize.textContent = formatBytes(data.totalSize);
    if (data.disk && Number.isFinite(data.disk.free)) {
      el.statFree.textContent = formatBytes(data.disk.free);
      el.statFree.title = `${formatBytes(data.disk.total)} total`;
    } else {
      el.statFree.textContent = "-";
      el.statFree.title = "";
    }
  }

  function compareNames(a, b) {
    return a.name.localeCompare(b.name, undefined, {
      numeric: true,
      sensitivity: "base",
    });
  }

  function compareEntries(a, b) {
    if (a.isDir !== b.isDir) {
      return a.isDir ? -1 : 1;
    }
    const { key, direction } = state.sort;
    let result = 0;
    if (key === "size") {
      result = (a.size || 0) - (b.size || 0);
    } else if (key === "mtime") {
      result = (a.mtime || 0) - (b.mtime || 0);
    }
    if (result === 0) {
      return compareNames(a, b);
    }
    return result * direction;
  }

  function sortedEntries() {
    const entries = state.listing ? state.listing.entries : [];
    return [...entries].sort(compareEntries);
  }

  function updateSortHeaders() {
    for (const th of document.querySelectorAll("th[data-sort-key]")) {
      const active = th.dataset.sortKey === state.sort.key;
      th.setAttribute(
        "aria-sort",
        active ? (state.sort.direction === 1 ? "ascending" : "descending") : "none",
      );
    }
  }

  function handleSortClick(key) {
    if (state.sort.key === key) {
      state.sort.direction *= -1;
    } else {
      state.sort.key = key;
      state.sort.direction = 1;
    }
    updateSortHeaders();
    renderTable();
  }

  function renderTable() {
    const data = state.listing;
    const entries = sortedEntries();
    const fragment = document.createDocumentFragment();

    for (const entry of entries) {
      const row = document.createElement("tr");
      row.dataset.name = entry.name;
      row.dataset.path = entry.path;

      const nameCell = document.createElement("td");
      const nameWrap = document.createElement("div");
      nameWrap.className = "name-cell";

      const iconWrap = document.createElement("span");
      iconWrap.className = `file-icon${entry.isDir ? " is-folder" : ""}`;
      iconWrap.appendChild(makeIcon(entry.isDir ? "folder" : "file"));

      let nameNode;
      if (entry.isDir) {
        nameNode = document.createElement("button");
        nameNode.type = "button";
        nameNode.className = "file-name";
        nameNode.addEventListener("click", () => {
          navigate(entry.path, { push: true });
        });
      } else if (entry.preview) {
        nameNode = document.createElement("button");
        nameNode.type = "button";
        nameNode.className = "file-name";
        nameNode.addEventListener("click", () => {
          openPreview(entry);
        });
        nameNode.title = `Preview ${entry.name}`;
      } else {
        nameNode = document.createElement("a");
        nameNode.className = "file-name";
        nameNode.href = downloadUrl(entry.path);
        nameNode.download = entry.name;
        nameNode.title = `Download ${entry.name}`;
      }
      nameNode.textContent = entry.name;
      nameNode.title = nameNode.title || entry.name;

      nameWrap.append(iconWrap, nameNode);
      nameCell.appendChild(nameWrap);

      const sizeCell = document.createElement("td");
      sizeCell.className = "size-cell";
      sizeCell.textContent = entry.isDir ? "-" : formatBytes(entry.size);

      const dateCell = document.createElement("td");
      dateCell.className = "date-cell";
      dateCell.textContent = formatDate(entry.mtime);

      const actionCell = document.createElement("td");
      actionCell.className = "action-column";
      const actions = document.createElement("div");
      actions.className = "row-actions";
      if (entry.isDir) {
        const openButton = document.createElement("button");
        openButton.type = "button";
        openButton.className = "icon-button";
        openButton.title = `Open ${entry.name}`;
        openButton.setAttribute("aria-label", `Open ${entry.name}`);
        openButton.appendChild(makeIcon("arrow"));
        openButton.addEventListener("click", () => {
          navigate(entry.path, { push: true });
        });
        actions.appendChild(openButton);
      } else {
        const downloadLink = document.createElement("a");
        downloadLink.className = "icon-button";
        downloadLink.href = downloadUrl(entry.path);
        downloadLink.download = entry.name;
        downloadLink.title = `Download ${entry.name}`;
        downloadLink.setAttribute("aria-label", `Download ${entry.name}`);
        downloadLink.appendChild(makeIcon("download"));
        actions.appendChild(downloadLink);
      }

      const pinned = state.quickPaths.has(entry.path);
      const pinButton = document.createElement("button");
      pinButton.type = "button";
      pinButton.className = "icon-button pin-button";
      pinButton.classList.toggle("is-active", pinned);
      pinButton.setAttribute("aria-pressed", String(pinned));
      pinButton.title = pinned
        ? `Remove ${entry.name} from quick access`
        : `Add ${entry.name} to quick access`;
      pinButton.setAttribute("aria-label", pinButton.title);
      pinButton.appendChild(makeIcon("pin"));
      pinButton.addEventListener("click", () => toggleQuick(entry, pinButton));
      actions.appendChild(pinButton);

      actionCell.appendChild(actions);

      row.append(nameCell, sizeCell, dateCell, actionCell);
      fragment.appendChild(row);
    }

    el.fileList.replaceChildren(fragment);

    if (entries.length === 0) {
      el.tableWrap.hidden = true;
      el.emptyState.hidden = false;
      el.emptyState.querySelector("use").setAttribute("href", "#i-folder");
      el.emptyTitle.textContent = "This folder is empty";
      el.emptyCopy.textContent = "Drop files above or create a folder.";
      el.emptyAction.hidden = true;
      state.emptyAction = null;
    } else {
      el.tableWrap.hidden = false;
      el.emptyState.hidden = true;
    }
    applyFilter();
  }

  function applyFilter() {
    const query = state.filter.trim().toLocaleLowerCase();
    let shown = 0;
    for (const row of el.fileList.children) {
      const match = !query || row.dataset.name.toLocaleLowerCase().includes(query);
      row.hidden = !match;
      if (match) {
        shown += 1;
      }
    }
    updateBrowserStatus(shown);
  }

  function applyQuickEntries(entries) {
    state.quickEntries = Array.isArray(entries) ? entries : [];
    state.quickPaths = new Set(state.quickEntries.map((item) => item.path));
    renderQuickAccess();
  }

  async function loadQuickAccess() {
    try {
      const data = await api("/api/quick-access");
      applyQuickEntries(data.entries);
    } catch (error) {
      if (error.status !== 401) {
        state.quickEntries = [];
        state.quickPaths = new Set();
        renderQuickAccess();
      }
    }
  }

  function quickItemNode(item) {
    const li = document.createElement("li");
    li.className = "quick-item";

    let link;
    if (item.isDir) {
      link = document.createElement("button");
      link.type = "button";
      link.addEventListener("click", () => navigate(item.path, { push: true }));
    } else if (item.preview) {
      link = document.createElement("button");
      link.type = "button";
      link.addEventListener("click", () => {
        openPreview({
          path: item.path,
          name: item.name,
          preview: item.preview,
          isDir: false,
        });
      });
    } else {
      link = document.createElement("a");
      link.href = downloadUrl(item.path);
      link.download = item.name;
    }
    link.className = "quick-link";
    link.title = item.path;

    const icon = document.createElement("span");
    icon.className = `quick-icon${item.isDir ? " is-folder" : ""}`;
    icon.appendChild(makeIcon(item.isDir ? "folder" : "file"));
    const label = document.createElement("span");
    label.className = "quick-name";
    label.textContent = item.name;
    link.append(icon, label);

    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "quick-remove icon-button";
    remove.title = `Remove ${item.name} from quick access`;
    remove.setAttribute("aria-label", remove.title);
    remove.appendChild(makeIcon("x"));
    remove.addEventListener("click", () => toggleQuick(item, remove));

    li.append(link, remove);
    return li;
  }

  function renderQuickAccess() {
    const count = state.quickEntries.length;
    el.quickCount.hidden = count === 0;
    el.quickCount.textContent = String(count);
    el.quickEmpty.hidden = count > 0;
    el.quickList.replaceChildren(...state.quickEntries.map(quickItemNode));
  }

  async function toggleQuick(entry, button) {
    const pinned = state.quickPaths.has(entry.path);
    button.disabled = true;
    try {
      const data = pinned
        ? await api("/api/quick-access/remove", {
            method: "POST",
            json: { path: entry.path },
          })
        : await api("/api/quick-access", {
            method: "POST",
            json: { path: entry.path },
          });
      applyQuickEntries(data.entries);
      if (state.listing) {
        renderTable();
      }
      toast(
        pinned
          ? `Removed "${entry.name}" from quick access.`
          : `Pinned "${entry.name}" to quick access.`,
        pinned ? "info" : "success",
      );
    } catch (error) {
      button.disabled = false;
      if (error.status !== 401) {
        toast(error.message, "error");
      }
    }
  }

  function updateBrowserStatus(shownOverride) {
    if (state.loading) {
      el.browserStatus.textContent = "Loading folder...";
      return;
    }
    if (!state.listing) {
      return;
    }
    const total = state.listing.entries.length;
    let shown = total;
    if (shownOverride !== undefined) {
      shown = shownOverride;
    } else if (state.filter.trim()) {
      const query = state.filter.trim().toLocaleLowerCase();
      shown = state.listing.entries.filter((entry) =>
        entry.name.toLocaleLowerCase().includes(query),
      ).length;
    }
    let text;
    if (state.filter.trim()) {
      text = `${integerFormatter.format(shown)} of ${integerFormatter.format(total)} ${plural(total, "item", "items")}`;
    } else {
      text = `${integerFormatter.format(total)} ${plural(total, "item", "items")}`;
    }
    if (!state.listing.writable) {
      text += " - read-only";
    }
    el.browserStatus.textContent = text;
  }

  function updateUploadAvailability() {
    const writable = Boolean(state.listing && state.listing.writable && state.session);
    const blocked = state.loading || !writable;
    el.uploadButton.disabled = blocked;
    el.browseButton.classList.toggle("is-disabled", blocked);
    el.newFolderButton.disabled = blocked;
    el.fileInput.disabled = blocked;
    el.refreshButton.disabled = state.loading || !state.listing;
    el.dropzone.classList.toggle("is-disabled", !writable);
    el.dropzone.setAttribute("aria-disabled", String(!writable));
    el.dropzone.tabIndex = writable ? 0 : -1;
    if (!state.listing) {
      el.dropHint.textContent = "Open a folder to upload files.";
      el.dropzone.setAttribute("aria-label", "Uploads are unavailable until a folder is loaded");
    } else if (!state.listing.writable) {
      el.dropHint.textContent = "This folder is read-only.";
      el.dropzone.setAttribute("aria-label", "Uploads are disabled because this folder is read-only");
    } else {
      const current = displayPath(state.listing.path);
      el.dropHint.textContent = `Files are saved to ${current}.`;
      el.dropzone.setAttribute("aria-label", `Upload files to ${current}`);
    }
  }

  function chooseFiles() {
    if (!state.listing || !state.listing.writable || state.loading) {
      return;
    }
    el.fileInput.click();
  }

  function queueUploads(fileList) {
    const files = Array.from(fileList || []);
    if (!files.length) {
      return;
    }
    if (!state.session) {
      showLogin("Sign in to upload files.");
      return;
    }
    if (!state.listing || !state.listing.writable) {
      toast("This folder is read-only.", "error");
      return;
    }
    const targetPath = state.path;
    const knownEntries = state.listing.entries;
    state.uploadChain = state.uploadChain
      .then(() => runUploadBatch(files, targetPath, knownEntries))
      .catch((error) => {
        console.error(error);
        toast("Upload failed unexpectedly.", "error");
      });
  }

  async function runUploadBatch(files, targetPath, knownEntries) {
    if (!state.session) {
      return;
    }
    state.uploadsActive += 1;
    el.uploadPanel.hidden = false;
    el.uploadSummary.textContent = `Preparing ${files.length} ${plural(files.length, "file", "files")}...`;

    const existingFiles = new Set(
      knownEntries.filter((entry) => !entry.isDir).map((entry) => entry.name),
    );
    const existingFolders = new Set(
      knownEntries.filter((entry) => entry.isDir).map((entry) => entry.name),
    );
    const conflicts = files.filter((file) => existingFiles.has(file.name));
    let overwriteAll = false;
    if (conflicts.length > 0) {
      overwriteAll = window.confirm(
        `${conflicts.length} ${plural(conflicts.length, "file already exists", "files already exist")} ` +
          `in this folder. Replace ${conflicts.length === 1 ? "it" : "them"}? ` +
          `Cancel will skip ${conflicts.length === 1 ? "that file" : "those files"}.`,
      );
    }

    let uploaded = 0;
    let skipped = 0;
    let failed = 0;

    try {
      for (let index = 0; index < files.length; index += 1) {
        const file = files[index];
        if (!state.session) {
          break;
        }
        el.uploadSummary.textContent = `Uploading ${index + 1} of ${files.length}...`;

        if (state.maxUpload && file.size > state.maxUpload) {
          const item = addUploadItem(file);
          markUploadFailed(item, `Exceeds the ${formatBytes(state.maxUpload)} upload limit.`);
          failed += 1;
          continue;
        }

        if (existingFolders.has(file.name)) {
          const item = addUploadItem(file);
          markUploadSkipped(item, "A folder uses this name.");
          skipped += 1;
          continue;
        }

        const isConflict = existingFiles.has(file.name);
        if (isConflict && !overwriteAll) {
          const item = addUploadItem(file);
          markUploadSkipped(item, "Already exists; not replaced.");
          skipped += 1;
          continue;
        }

        const item = addUploadItem(file);
        try {
          await uploadOne(file, targetPath, isConflict, item);
          markUploadDone(item, isConflict);
          uploaded += 1;
          existingFiles.add(file.name);
        } catch (error) {
          if (error.status === 401) {
            markUploadFailed(item, "Session expired.");
            failed += 1;
            break;
          }
          if (error.status === 409 && !isConflict) {
            const replace = window.confirm(`"${file.name}" already exists. Replace it?`);
            if (replace) {
              try {
                await uploadOne(file, targetPath, true, item);
                markUploadDone(item, true);
                uploaded += 1;
                existingFiles.add(file.name);
                continue;
              } catch (retryError) {
                markUploadFailed(item, retryError.message);
                failed += 1;
                if (retryError.status === 401) {
                  break;
                }
                continue;
              }
            }
            markUploadSkipped(item, "Already exists; not replaced.");
            skipped += 1;
            continue;
          }
          markUploadFailed(item, error.message);
          failed += 1;
        }
      }
    } finally {
      state.uploadsActive = Math.max(0, state.uploadsActive - 1);
    }

    const parts = [];
    if (uploaded) {
      parts.push(`${uploaded} ${plural(uploaded, "file", "files")} uploaded`);
    }
    if (skipped) {
      parts.push(`${skipped} ${plural(skipped, "file", "files")} skipped`);
    }
    if (failed) {
      parts.push(`${failed} ${plural(failed, "file", "files")} failed`);
    }
    el.uploadSummary.textContent = parts.length
      ? `${parts.join(" - ")}.`
      : "No files were uploaded.";

    if (state.session && state.path === targetPath) {
      await navigate(targetPath, { resetFilter: false });
    }

    if (parts.length) {
      const kind = failed ? "error" : uploaded ? "success" : "info";
      toast(`${parts.join(". ")}.`, kind);
    }
  }

  function addUploadItem(file) {
    el.uploadPanel.hidden = false;

    const row = document.createElement("div");
    row.className = "upload-item";

    const copy = document.createElement("div");
    copy.className = "upload-copy";
    const name = document.createElement("span");
    name.className = "upload-name";
    name.textContent = file.name;
    name.title = file.name;
    const meta = document.createElement("span");
    meta.className = "upload-meta";
    meta.textContent = formatBytes(file.size);
    copy.append(name, meta);

    const status = document.createElement("span");
    status.className = "upload-status";
    status.textContent = "Queued";

    const track = document.createElement("div");
    track.className = "progress-track";
    track.setAttribute("role", "progressbar");
    track.setAttribute("aria-label", `Upload progress for ${file.name}`);
    track.setAttribute("aria-valuemin", "0");
    track.setAttribute("aria-valuemax", "100");
    track.setAttribute("aria-valuenow", "0");
    const bar = document.createElement("span");
    bar.className = "progress-bar";
    track.appendChild(bar);

    row.append(copy, status, track);
    el.uploadList.appendChild(row);

    return { row, meta, status, bar, track };
  }

  function setUploadProgress(item, percent, label) {
    const value = Math.max(0, Math.min(100, percent));
    item.bar.style.width = `${value}%`;
    item.track.setAttribute("aria-valuenow", String(Math.round(value)));
    if (label) {
      item.status.textContent = label;
    }
  }

  function markUploadDone(item, replaced) {
    item.row.classList.remove("is-error", "is-skipped");
    item.row.classList.add("is-done");
    item.status.textContent = replaced ? "Replaced" : "Uploaded";
    setUploadProgress(item, 100);
  }

  function markUploadFailed(item, message) {
    item.row.classList.remove("is-done", "is-skipped");
    item.row.classList.add("is-error");
    item.status.textContent = "Failed";
    item.meta.textContent = message;
    item.meta.title = message;
    item.track.setAttribute("aria-valuetext", message);
  }

  function markUploadSkipped(item, message) {
    item.row.classList.remove("is-done", "is-error");
    item.row.classList.add("is-skipped");
    item.status.textContent = "Skipped";
    item.meta.textContent = message;
    item.meta.title = message;
    item.track.setAttribute("aria-valuetext", message);
  }

  function uploadOne(file, targetPath, overwrite, item) {
    return new Promise((resolve, reject) => {
      const params = new URLSearchParams({
        path: targetPath,
        name: file.name,
        overwrite: overwrite ? "1" : "0",
      });
      const xhr = new XMLHttpRequest();
      xhr.open("PUT", `/api/upload?${params.toString()}`);
      xhr.setRequestHeader("X-LanVault-Request", "1");
      xhr.setRequestHeader("Content-Type", "application/octet-stream");

      item.row.classList.remove("is-done", "is-error", "is-skipped");
      item.status.textContent = "Uploading";
      setUploadProgress(item, 0);

      xhr.upload.addEventListener("progress", (event) => {
        if (!event.lengthComputable || event.total <= 0) {
          return;
        }
        const percent = (event.loaded / event.total) * 100;
        setUploadProgress(
          item,
          Math.min(percent, 99),
          percent >= 99.5 ? "Finishing" : `Uploading ${Math.floor(percent)}%`,
        );
      });

      xhr.addEventListener("load", () => {
        let data = null;
        try {
          data = JSON.parse(xhr.responseText);
        } catch (error) {
          data = null;
        }
        if (xhr.status >= 200 && xhr.status < 300) {
          setUploadProgress(item, 100);
          resolve(data);
          return;
        }
        if (xhr.status === 401) {
          showLogin("Your session expired. Sign in again.");
        }
        const message =
          data && data.error ? data.error : `Upload failed (${xhr.status}).`;
        reject(new ApiError(xhr.status, message));
      });

      xhr.addEventListener("error", () => {
        reject(new ApiError(0, "Network error while uploading."));
      });

      xhr.addEventListener("abort", () => {
        reject(new ApiError(0, "Upload aborted."));
      });

      xhr.send(file);
    });
  }

  function clearFinishedUploads() {
    for (const row of Array.from(el.uploadList.children)) {
      if (
        row.classList.contains("is-done") ||
        row.classList.contains("is-error") ||
        row.classList.contains("is-skipped")
      ) {
        row.remove();
      }
    }
    if (!el.uploadList.children.length) {
      el.uploadPanel.hidden = true;
      el.uploadSummary.textContent = "Waiting to upload.";
    }
  }

  function resetPreviewBody() {
    if (state.previewAbort) {
      state.previewAbort.abort();
      state.previewAbort = null;
    }
    state.previewToken += 1;
    el.previewBody.replaceChildren();
    el.previewBody.className = "preview-body";
    el.previewBody.setAttribute("aria-busy", "false");
    el.previewFooter.hidden = true;
    el.previewNote.textContent = "";
  }

  function closePreview() {
    if (el.previewDialog.open) {
      el.previewDialog.close();
    }
  }

  function showPreviewError(message, token) {
    if (token !== undefined && token !== state.previewToken) {
      return;
    }
    state.previewAbort = null;
    el.previewBody.className = "preview-body is-message";
    el.previewBody.setAttribute("aria-busy", "false");
    const box = document.createElement("div");
    box.className = "preview-error";
    const title = document.createElement("strong");
    title.textContent = "Preview unavailable";
    const detail = document.createElement("span");
    detail.textContent = message;
    box.append(title, detail);
    el.previewBody.replaceChildren(box);
  }

  function showPreviewLoading(message = "Loading preview...") {
    el.previewBody.className = "preview-body is-document";
    el.previewBody.setAttribute("aria-busy", "true");
    const loading = document.createElement("div");
    loading.className = "preview-loading";
    loading.textContent = message;
    el.previewBody.replaceChildren(loading);
  }

  async function loadTextPreview(entry, url, token) {
    const limit = TEXT_PREVIEW_LIMIT;
    const knownSize = Number.isFinite(entry.size) ? entry.size : null;
    // Quick access entries carry no size, so cap by Range whenever it is unknown.
    const useRange = knownSize === null || knownSize > limit;
    const headers = useRange ? { Range: `bytes=0-${limit - 1}` } : {};
    const controller = new AbortController();
    state.previewAbort = controller;
    try {
      const response = await fetch(url, {
        headers,
        credentials: "same-origin",
        signal: controller.signal,
      });
      if (token !== state.previewToken) {
        return;
      }
      if (response.status === 401) {
        closePreview();
        showLogin("Your session expired. Sign in again.");
        return;
      }
      if (response.status === 416 && useRange) {
        // An empty file has no satisfiable range.
        state.previewAbort = null;
        const pre = document.createElement("pre");
        pre.className = "preview-text";
        pre.tabIndex = 0;
        pre.textContent = "This file is empty.";
        el.previewBody.className = "preview-body is-document";
        el.previewBody.setAttribute("aria-busy", "false");
        el.previewBody.replaceChildren(pre);
        return;
      }
      if (!response.ok) {
        const message =
          response.status === 404
            ? "This file is no longer available."
            : `The preview request failed (${response.status}).`;
        throw new ApiError(response.status, message);
      }
      let totalSize = knownSize;
      if (response.status === 206) {
        const match = /\/(\d+)\s*$/.exec(
          response.headers.get("content-range") || "",
        );
        if (match) {
          totalSize = Number(match[1]);
        }
      }
      const truncated =
        totalSize !== null && Number.isFinite(totalSize) && totalSize > limit;
      const data = await response.arrayBuffer();
      if (token !== state.previewToken) {
        return;
      }
      state.previewAbort = null;
      const text = new TextDecoder("utf-8").decode(data);
      const pre = document.createElement("pre");
      pre.className = "preview-text";
      pre.tabIndex = 0;
      pre.textContent = text || "This file is empty.";
      el.previewBody.className = "preview-body is-document";
      el.previewBody.setAttribute("aria-busy", "false");
      el.previewBody.replaceChildren(pre);
      if (truncated) {
        el.previewFooter.hidden = false;
        el.previewNote.textContent =
          `Showing the first ${formatBytes(limit)} of ${formatBytes(totalSize)}. ` +
          "Download the file to see all of it.";
      }
    } catch (error) {
      if (error.name === "AbortError" || token !== state.previewToken) {
        return;
      }
      showPreviewError(error.message || "Could not load the text preview.", token);
    }
  }

  function previewSequence() {
    if (!state.listing) {
      return [];
    }
    const query = state.filter.trim().toLocaleLowerCase();
    return sortedEntries().filter(
      (entry) =>
        entry.preview &&
        (!query || entry.name.toLocaleLowerCase().includes(query)),
    );
  }

  function updatePreviewNav() {
    const total = state.previewList.length;
    const showNav = total > 1;
    el.previewNav.hidden = !showNav;
    el.previewPrev.disabled = state.previewIndex <= 0;
    el.previewNext.disabled = state.previewIndex >= total - 1;
    el.previewCount.textContent = showNav
      ? `${state.previewIndex + 1} / ${total}`
      : "";
  }

  function stepPreview(delta) {
    const next = state.previewIndex + delta;
    if (next < 0 || next >= state.previewList.length) {
      return;
    }
    state.previewIndex = next;
    renderPreview(state.previewList[next]);
  }

  function openPreview(entry) {
    if (!entry || !entry.preview) {
      return;
    }
    state.previewList = previewSequence();
    let index = state.previewList.findIndex((item) => item.path === entry.path);
    if (index < 0) {
      state.previewList = [entry];
      index = 0;
    }
    state.previewIndex = index;
    if (!el.previewDialog.open) {
      el.previewDialog.showModal();
    }
    el.previewClose.focus();
    renderPreview(entry);
  }

  function renderPreview(entry) {
    resetPreviewBody();
    const token = state.previewToken;
    const url = previewUrl(entry.path);
    el.previewTitle.textContent = entry.name;
    el.previewTitle.title = entry.name;
    el.previewDownload.href = downloadUrl(entry.path);
    el.previewDownload.download = entry.name;
    el.previewDownload.title = `Download ${entry.name}`;
    el.previewDownload.setAttribute("aria-label", `Download ${entry.name}`);
    updatePreviewNav();

    const body = el.previewBody;
    if (entry.preview === "text") {
      showPreviewLoading();
      loadTextPreview(entry, url, token);
      return;
    }

    if (entry.preview === "image") {
      body.setAttribute("aria-busy", "true");
      const image = document.createElement("img");
      image.className = "preview-image";
      image.alt = entry.name;
      image.addEventListener("load", () => {
        if (token === state.previewToken) {
          body.setAttribute("aria-busy", "false");
        }
      });
      image.addEventListener("error", () => {
        showPreviewError("The browser could not display this image.", token);
      });
      image.src = url;
      body.appendChild(image);
      return;
    }

    if (entry.preview === "video" || entry.preview === "audio") {
      body.setAttribute("aria-busy", "true");
      const media = document.createElement(entry.preview === "video" ? "video" : "audio");
      media.className = entry.preview === "video" ? "preview-video" : "preview-audio";
      media.controls = true;
      media.preload = "metadata";
      if (entry.preview === "video") {
        media.playsInline = true;
      }
      media.addEventListener("loadedmetadata", () => {
        if (token === state.previewToken) {
          body.setAttribute("aria-busy", "false");
        }
      });
      media.addEventListener("error", () => {
        showPreviewError(
          "The browser could not play this file. The format or codec may be unsupported.",
          token,
        );
      });
      media.src = url;

      if (entry.preview === "audio") {
        const wrap = document.createElement("div");
        wrap.className = "preview-audio-wrap";
        const art = document.createElement("span");
        art.className = "preview-audio-art";
        art.appendChild(makeIcon("music"));
        wrap.append(art, media);
        body.appendChild(wrap);
      } else {
        body.appendChild(media);
      }
      return;
    }

    if (entry.preview === "pdf") {
      body.className = "preview-body is-pdf";
      body.setAttribute("aria-busy", "true");
      const frame = document.createElement("iframe");
      frame.className = "preview-frame";
      frame.title = `Preview of ${entry.name}`;
      frame.referrerPolicy = "no-referrer";
      frame.addEventListener("load", () => {
        if (token === state.previewToken) {
          body.setAttribute("aria-busy", "false");
        }
      });
      frame.src = url;
      body.appendChild(frame);
    }
  }

  function openMkdirDialog() {
    if (!state.listing || !state.listing.writable) {
      toast("This folder is read-only.", "error");
      return;
    }
    el.mkdirForm.reset();
    el.mkdirError.hidden = true;
    el.mkdirError.textContent = "";
    el.mkdirSubmit.disabled = false;
    el.mkdirDialog.showModal();
    window.setTimeout(() => el.mkdirName.focus(), 20);
  }

  function closeMkdirDialog() {
    if (el.mkdirDialog.open) {
      el.mkdirDialog.close();
    }
  }

  function setMkdirError(message) {
    el.mkdirError.textContent = message;
    el.mkdirError.hidden = !message;
  }

  async function handleMkdir(event) {
    event.preventDefault();
    const name = el.mkdirName.value;
    if (!name) {
      setMkdirError("Enter a folder name.");
      el.mkdirName.focus();
      return;
    }
    if (!state.listing || !state.listing.writable) {
      setMkdirError("This folder is read-only.");
      return;
    }
    setMkdirError("");
    el.mkdirSubmit.disabled = true;
    try {
      await api("/api/mkdir", {
        method: "POST",
        json: { path: state.path, name },
      });
      closeMkdirDialog();
      await navigate(state.path, { resetFilter: false });
      toast(`Created folder "${name}".`, "success");
    } catch (error) {
      if (error.status !== 401) {
        setMkdirError(error.message);
      }
    } finally {
      el.mkdirSubmit.disabled = false;
    }
  }

  function bindEvents() {
    for (const button of document.querySelectorAll(".sort-button")) {
      button.addEventListener("click", () => handleSortClick(button.dataset.sort));
    }

    el.loginForm.addEventListener("submit", handleLogin);
    el.logoutButton.addEventListener("click", handleLogout);
    el.keysButton.addEventListener("click", openKeysDialog);
    el.keysClose.addEventListener("click", closeKeysDialog);
    el.keysDone.addEventListener("click", closeKeysDialog);
    el.keysEnable.addEventListener("click", enableCurrentBrowser);
    el.refreshButton.addEventListener("click", () => {
      navigate(state.path, { resetFilter: false });
    });
    el.newFolderButton.addEventListener("click", openMkdirDialog);
    el.uploadButton.addEventListener("click", chooseFiles);
    el.fileInput.addEventListener("change", () => {
      const files = Array.from(el.fileInput.files || []);
      el.fileInput.value = "";
      queueUploads(files);
    });

    el.filterInput.addEventListener("input", () => {
      state.filter = el.filterInput.value;
      applyFilter();
    });

    el.dropzone.addEventListener("click", (event) => {
      if (event.target.closest("button, a, input")) {
        return;
      }
      chooseFiles();
    });

    el.dropzone.addEventListener("keydown", (event) => {
      if (event.target !== el.dropzone) {
        return;
      }
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        chooseFiles();
      }
    });

    let dragDepth = 0;
    el.dropzone.addEventListener("dragenter", (event) => {
      if (!Array.from(event.dataTransfer.types || []).includes("Files")) {
        return;
      }
      event.preventDefault();
      dragDepth += 1;
      el.dropzone.classList.add("is-dragging");
    });
    el.dropzone.addEventListener("dragover", (event) => {
      event.preventDefault();
      if (event.dataTransfer) {
        event.dataTransfer.dropEffect = "copy";
      }
    });
    el.dropzone.addEventListener("dragleave", (event) => {
      event.preventDefault();
      dragDepth = Math.max(0, dragDepth - 1);
      if (dragDepth === 0) {
        el.dropzone.classList.remove("is-dragging");
      }
    });
    el.dropzone.addEventListener("drop", (event) => {
      event.preventDefault();
      dragDepth = 0;
      el.dropzone.classList.remove("is-dragging");
      if (!state.listing || !state.listing.writable) {
        toast("This folder is read-only.", "error");
        return;
      }
      const files = Array.from(event.dataTransfer.files || []);
      queueUploads(files);
    });

    window.addEventListener("dragover", (event) => {
      event.preventDefault();
    });
    window.addEventListener("drop", (event) => {
      event.preventDefault();
    });

    el.clearUploadsButton.addEventListener("click", clearFinishedUploads);
    el.mkdirForm.addEventListener("submit", handleMkdir);
    el.mkdirClose.addEventListener("click", closeMkdirDialog);
    el.mkdirCancel.addEventListener("click", closeMkdirDialog);
    el.emptyAction.addEventListener("click", () => {
      if (state.emptyAction) {
        state.emptyAction();
      }
    });

    el.previewClose.addEventListener("click", closePreview);
    el.previewPrev.addEventListener("click", () => stepPreview(-1));
    el.previewNext.addEventListener("click", () => stepPreview(1));
    el.previewDialog.addEventListener("keydown", (event) => {
      if (
        event.target.closest &&
        event.target.closest("input, textarea, select, pre, video, audio, iframe")
      ) {
        return;
      }
      if (event.key === "ArrowLeft") {
        event.preventDefault();
        stepPreview(-1);
      } else if (event.key === "ArrowRight") {
        event.preventDefault();
        stepPreview(1);
      }
    });
    el.previewDialog.addEventListener("close", () => {
      resetPreviewBody();
      state.previewList = [];
      state.previewIndex = -1;
    });
    el.previewDialog.addEventListener("click", (event) => {
      if (event.target !== el.previewDialog) {
        return;
      }
      const rect = el.previewDialog.getBoundingClientRect();
      if (
        event.clientX < rect.left ||
        event.clientX > rect.right ||
        event.clientY < rect.top ||
        event.clientY > rect.bottom
      ) {
        closePreview();
      }
    });

    window.addEventListener("popstate", () => {
      if (el.previewDialog.open) {
        closePreview();
      }
      const path = pathFromLocation();
      navigate(path, { push: false }).then((ok) => {
        if (!ok && path && state.session) {
          toast("That folder was not found. Opened the root folder.", "error");
          navigate("", { push: false });
        }
      });
    });
  }

  async function init() {
    cacheElements();
    bindEvents();
    try {
      const session = await api("/api/session");
      await startApp(session);
    } catch (error) {
      if (error.status === 401) {
        const session = await attemptPublicKeyLogin();
        if (session) {
          await startApp(session);
        } else {
          showLogin();
        }
      } else {
        showLogin(error.message || "Cannot load LanVault.");
      }
    } finally {
      el.boot.hidden = true;
    }
  }

  init();
})();
