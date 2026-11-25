(function () {
  "use strict";

  const DEFAULT_DIRECT_PORTS = [21, 22, 25, 1433, 1521, 3306, 5432, 6379, 27017];

  const KNOWN_PORT_LABELS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    110: "POP3",
    143: "IMAP",
    389: "LDAP",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    2181: "ZK",
    3306: "MySQL",
    3389: "RDP",
    5432: "PG",
    5672: "AMQP",
    6379: "Redis",
    9092: "Kafka",
    9200: "ES",
    27017: "Mongo",
  };

  const state = {
    connections: [],
    bufferedSnapshot: null,
    paused: false,
    capacity: 200,
    bypassAll: false,
    actionFilter: "ALL",
    keyword: "",
    pollTimer: null,
    sessionToken: "",

    savedBurpAddr: "",
    savedPortsKey: "",
    portsList: [],
    rawPortsMode: false,

    bridgeState: "Stopped",
    bridgePID: 0,
    bridgeIsAdmin: null,
    bridgeRequestPending: false,
    selectedProcs: [],
    bridgeHydrated: false,
    processesEdited: false,
    targetDomainsEdited: false,
    runningProcesses: [],
    processMetaMap: {},
    procFilter: "",
    targetDomains: "*",

    activeSheet: null, // "settings" | "logs" | null
    lastLogsText: "",
    certStatus: null,
    certBusy: false,
  };

  const SESSION_STORAGE_KEY = "cs_burp_router_session";

  function loadSessionToken() {
    const launchToken = new URLSearchParams(window.location.hash.slice(1)).get("session");
    if (launchToken) {
      window.history.replaceState(null, "", window.location.pathname + window.location.search);
    }
    try {
      if (launchToken) window.sessionStorage.setItem(SESSION_STORAGE_KEY, launchToken);
      return launchToken || window.sessionStorage.getItem(SESSION_STORAGE_KEY) || "";
    } catch (_) {
      return launchToken || "";
    }
  }

  function apiFetch(path, options = {}) {
    const headers = new Headers(options.headers);
    headers.set("Authorization", "Bearer " + state.sessionToken);
    return fetch(path, { ...options, headers, cache: "no-store", mode: "same-origin" });
  }

  const els = {
    socksAddrDisplay: document.getElementById("socksAddrDisplay"),
    emptySocksCode: document.getElementById("emptySocksCode"),
    copySocksBtn: document.getElementById("copySocksBtn"),
    copySocksHint: document.getElementById("copySocksHint"),
    syncDot: document.getElementById("syncDot"),
    syncText: document.getElementById("syncText"),

    modeSmartBtn: document.getElementById("modeSmartBtn"),
    modeBypassBtn: document.getElementById("modeBypassBtn"),
    certQuickBtn: document.getElementById("certQuickBtn"),
    certQuickDot: document.getElementById("certQuickDot"),
    certQuickText: document.getElementById("certQuickText"),
    openSettingsBtn: document.getElementById("openSettingsBtn"),
    dirtyDot: document.getElementById("dirtyDot"),
    openLogsBtn: document.getElementById("openLogsBtn"),
    logsCountBadge: document.getElementById("logsCountBadge"),
    themeToggleBtn: document.getElementById("themeToggleBtn"),

    bypassBanner: document.getElementById("bypassBanner"),
    restoreSmartBtn: document.getElementById("restoreSmartBtn"),
    nonAdminWarning: document.getElementById("nonAdminWarning"),

    bridgeStatePill: document.getElementById("bridgeStatePill"),
    bridgeDot: document.getElementById("bridgeDot"),
    bridgeStateText: document.getElementById("bridgeStateText"),
    procInputArea: document.getElementById("procInputArea"),
    selectedProcsChips: document.getElementById("selectedProcsChips"),
    procAddInput: document.getElementById("procAddInput"),
    bridgeProcsInput: document.getElementById("bridgeProcsInput"),
    refreshProcsBtn: document.getElementById("refreshProcsBtn"),
    procPickerDrawer: document.getElementById("procPickerDrawer"),
    procFilterInput: document.getElementById("procFilterInput"),
    procMatchCount: document.getElementById("procMatchCount"),
    closePickerBtn: document.getElementById("closePickerBtn"),
    procCheckboxList: document.getElementById("procCheckboxList"),

    summaryConfigBtn: document.getElementById("summaryConfigBtn"),
    burpAddrTopDisplay: document.getElementById("burpAddrTopDisplay"),
    portsCountSummary: document.getElementById("portsCountSummary"),
    bridgeStartBtn: document.getElementById("bridgeStartBtn"),
    bridgeStopBtn: document.getElementById("bridgeStopBtn"),
    bridgeErrorBar: document.getElementById("bridgeErrorBar"),
    bridgeFeedback: document.getElementById("bridgeFeedback"),

    filterTabs: Array.from(document.querySelectorAll(".filter-tab")),
    countAll: document.getElementById("countAll"),
    countBurp: document.getElementById("countBurp"),
    countDirect: document.getElementById("countDirect"),
    countError: document.getElementById("countError"),
    keywordInput: document.getElementById("keywordInput"),
    searchSlashHint: document.getElementById("searchSlashHint"),
    pauseStreamBtn: document.getElementById("pauseStreamBtn"),
    clearBtn: document.getElementById("clearBtn"),
    capacityHint: document.getElementById("capacityHint"),
    connTableBody: document.getElementById("connTableBody"),
    emptyStatePanel: document.getElementById("emptyStatePanel"),
    emptyTitle: document.getElementById("emptyTitle"),
    emptyDesc: document.getElementById("emptyDesc"),
    resetFilterBtn: document.getElementById("resetFilterBtn"),

    drawerBackdrop: document.getElementById("drawerBackdrop"),
    settingsDrawer: document.getElementById("settingsDrawer"),
    closeSettingsBtn: document.getElementById("closeSettingsBtn"),
    cancelSettingsBtn: document.getElementById("cancelSettingsBtn"),
    configForm: document.getElementById("configForm"),
    burpAddrInput: document.getElementById("burpAddrInput"),
    certStatusBadge: document.getElementById("certStatusBadge"),
    certMetaText: document.getElementById("certMetaText"),
    installCertBtn: document.getElementById("installCertBtn"),
    downloadCertBtn: document.getElementById("downloadCertBtn"),
    uninstallCertBtn: document.getElementById("uninstallCertBtn"),
    portChipsEditor: document.getElementById("portChipsEditor"),
    portChipsList: document.getElementById("portChipsList"),
    portAddInput: document.getElementById("portAddInput"),
    rawPortsEditor: document.getElementById("rawPortsEditor"),
    directPortsInput: document.getElementById("directPortsInput"),
    toggleRawPortsBtn: document.getElementById("toggleRawPortsBtn"),
    resetDefaultPortsBtn: document.getElementById("resetDefaultPortsBtn"),
    radioCards: Array.from(document.querySelectorAll(".radio-card")),
    targetDomainsSelect: document.getElementById("targetDomainsSelect"),
    configFeedback: document.getElementById("configFeedback"),

    logsDrawer: document.getElementById("logsDrawer"),
    closeLogsBtn: document.getElementById("closeLogsBtn"),
    bridgeBinDisplay: document.getElementById("bridgeBinDisplay"),
    copyLogsBtn: document.getElementById("copyLogsBtn"),
    refreshLogsBtn: document.getElementById("refreshLogsBtn"),
    engineLogsPre: document.getElementById("engineLogsPre"),
  };

  /* ------------------------------------------------------------------------
     Theme & Sheet Navigation
     ------------------------------------------------------------------------ */

  function initTheme() {
    try {
      const saved = window.localStorage.getItem("cs_burp_minimal_theme");
      if (saved === "light" || saved === "dark") {
        document.documentElement.setAttribute("data-theme", saved);
      }
    } catch (_) {}
  }

  function toggleTheme() {
    const cur = document.documentElement.getAttribute("data-theme") || "light";
    const next = cur === "light" ? "dark" : "light";
    document.documentElement.setAttribute("data-theme", next);
    try {
      window.localStorage.setItem("cs_burp_minimal_theme", next);
    } catch (_) {}
  }

  function openSheet(which) {
    state.activeSheet = which;
    const isSettings = which === "settings";
    const isLogs = which === "logs";
    els.drawerBackdrop.classList.toggle("hidden", !which);
    els.settingsDrawer.classList.toggle("hidden", !isSettings);
    els.logsDrawer.classList.toggle("hidden", !isLogs);
    if (isSettings) {
      fetchCertStatus();
    }
    if (isLogs) {
      fetchBridgeStatus();
    }
  }

  function closeSheets() {
    openSheet(null);
  }

  /* ------------------------------------------------------------------------
     Clipboard & Subtle Feedback
     ------------------------------------------------------------------------ */

  async function copyText(text) {
    if (!text) return false;
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch (_) {}
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try {
      ok = document.execCommand("copy");
    } catch (_) {}
    document.body.removeChild(ta);
    return ok;
  }

  function showToast(text, isError) {
    if (!text) return;
    els.bridgeFeedback.textContent = text;
    els.bridgeFeedback.classList.toggle("error", Boolean(isError));
    els.bridgeFeedback.classList.remove("hidden");
    window.clearTimeout(els.bridgeFeedback._timer);
    els.bridgeFeedback._timer = window.setTimeout(function () {
      els.bridgeFeedback.classList.add("hidden");
    }, 2800);
  }

  function showSheetFeedback(text, isError, isWarning = false) {
    els.configFeedback.textContent = text || "";
    els.configFeedback.classList.toggle("error", Boolean(isError));
    els.configFeedback.classList.toggle("warning", isWarning && !isError);
    window.clearTimeout(els.configFeedback._timer);
    if (text) {
      els.configFeedback._timer = window.setTimeout(function () {
        els.configFeedback.textContent = "";
      }, 3200);
    }
  }

  /* ------------------------------------------------------------------------
     Routing Config & Port Chips
     ------------------------------------------------------------------------ */

  function normalizePorts(ports) {
    const seen = new Set();
    const out = [];
    for (const p of ports) {
      const n = Number(p);
      if (Number.isInteger(n) && n >= 1 && n <= 65535 && !seen.has(n)) {
        seen.add(n);
        out.push(n);
      }
    }
    out.sort(function (a, b) { return a - b; });
    return out;
  }

  function parsePortsString(raw) {
    const trimmed = raw.trim();
    if (!trimmed) return [];
    const parts = trimmed.split(/[\s,，;；]+/).filter(Boolean);
    const nums = [];
    for (const part of parts) {
      if (!/^\d+$/.test(part)) {
        throw new Error("无效端口号: " + part);
      }
      const num = Number(part);
      if (num < 1 || num > 65535) {
        throw new Error("端口超出范围 (1-65535): " + part);
      }
      nums.push(num);
    }
    return normalizePorts(nums);
  }

  function updateDirtyIndicator() {
    const curBurp = els.burpAddrInput.value.trim();
    let curPortsKey = state.portsList.join(",");
    if (state.rawPortsMode) {
      try {
        curPortsKey = parsePortsString(els.directPortsInput.value).join(",");
      } catch (_) {
        curPortsKey = "__invalid__";
      }
    }
    const dirty =
      (state.savedBurpAddr !== "" && curBurp !== state.savedBurpAddr) ||
      curPortsKey !== state.savedPortsKey;
    els.dirtyDot.classList.toggle("hidden", !dirty);
  }

  function syncPortsUI() {
    els.directPortsInput.value = state.portsList.join(", ");
    const frag = document.createDocumentFragment();
    for (const port of state.portsList) {
      const chip = document.createElement("span");
      chip.className = "chip-pill";

      const num = document.createElement("span");
      num.textContent = String(port);
      chip.appendChild(num);

      const label = KNOWN_PORT_LABELS[port];
      if (label) {
        const sub = document.createElement("span");
        sub.className = "chip-sub";
        sub.textContent = label;
        chip.appendChild(sub);
      }

      const rm = document.createElement("button");
      rm.type = "button";
      rm.textContent = "×";
      rm.title = "移除端口 " + port;
      rm.addEventListener("click", function () {
        state.portsList = state.portsList.filter(function (p) { return p !== port; });
        syncPortsUI();
      });
      chip.appendChild(rm);
      frag.appendChild(chip);
    }
    els.portChipsList.replaceChildren(frag);
    updateDirtyIndicator();
  }

  function addPortsFromEntry(rawText) {
    if (!rawText.trim()) return true;
    try {
      const added = parsePortsString(rawText);
      state.portsList = normalizePorts(state.portsList.concat(added));
      els.portAddInput.value = "";
      syncPortsUI();
      return true;
    } catch (err) {
      showSheetFeedback(err.message, true);
      return false;
    }
  }

  function applyConfigToUI(cfg) {
    if (!cfg) return;
    const socks = cfg.socksListenAddr || "127.0.0.1:10808";
    els.socksAddrDisplay.textContent = socks;
    if (els.emptySocksCode) els.emptySocksCode.textContent = socks;

    const burp = cfg.burpAddr || "";
    state.savedBurpAddr = burp;
    els.burpAddrTopDisplay.textContent = burp || "-";
    if (document.activeElement !== els.burpAddrInput) {
      els.burpAddrInput.value = burp;
    }

    const ports = Array.isArray(cfg.directPorts) ? normalizePorts(cfg.directPorts) : [];
    state.savedPortsKey = ports.join(",");
    els.portsCountSummary.textContent = ports.length + " 端口直连";

    if (
      document.activeElement !== els.directPortsInput &&
      document.activeElement !== els.portAddInput
    ) {
      state.portsList = ports;
      syncPortsUI();
    } else {
      updateDirtyIndicator();
    }

    state.bypassAll = Boolean(cfg.bypassAll);
    els.modeSmartBtn.classList.toggle("active", !state.bypassAll);
    els.modeBypassBtn.classList.toggle("active", state.bypassAll);
    els.bypassBanner.classList.toggle("hidden", !state.bypassAll);
  }

  async function loadConfig() {
    try {
      const resp = await apiFetch("/api/config");
      if (resp.status === 401) {
        showSessionError();
        return false;
      }
      if (!resp.ok) throw new Error("配置读取失败 (" + resp.status + ")");
      applyConfigToUI(await resp.json());
      return true;
    } catch (err) {
      showToast(err.message, true);
      return false;
    }
  }

  async function updateConfig(payload, msg, fromSheet) {
    try {
      const resp = await apiFetch("/api/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || "保存失败");
      applyConfigToUI(data);
      fetchCertStatus();
      if (fromSheet) {
        showSheetFeedback(msg || "更改已保存并生效", false);
      } else {
        showToast(msg || "模式已更新", false);
      }
    } catch (err) {
      if (fromSheet) {
        showSheetFeedback(err.message, true);
      } else {
        showToast(err.message, true);
      }
    }
  }

  /* ------------------------------------------------------------------------
     Burp CA One-Click Install & Cleanup
     ------------------------------------------------------------------------ */

  function shortFingerprint(fp) {
    if (!fp || fp.length < 12) return fp || "";
    return fp.slice(0, 8) + "..." + fp.slice(-6);
  }

  function formatScopeLabel(scope) {
    if (!scope) return "";
    const parts = [];
    if (scope.includes("LocalMachine")) parts.push("系统级");
    if (scope.includes("CurrentUser")) parts.push("当前用户");
    return parts.join(" + ") || scope;
  }

  function applyCertStatus(st) {
    if (!st) return;
    state.certStatus = st;

    const hasAnyInstalled = Boolean(st.installed) || Number(st.legacyCount || 0) > 0;
    els.uninstallCertBtn.classList.toggle("hidden", !hasAnyInstalled);

    if (st.installed) {
      els.certQuickDot.className = "dot online";
      els.certQuickText.textContent = "证书已装";
      els.certQuickBtn.title = "当前 Burp 根证书已信任（点击查看详情或撤场清理）";

      const scopeText = formatScopeLabel(st.installedScope);
      els.certStatusBadge.className = "cert-badge installed";
      els.certStatusBadge.textContent = scopeText ? "已信任 · " + scopeText : "已信任";
      els.installCertBtn.textContent = "重新安装";
      els.certMetaText.textContent =
        (st.commonName || "PortSwigger CA") +
        " · SHA-256 " +
        shortFingerprint(st.fingerprintSHA256) +
        (st.notAfter ? " · 有效期至 " + st.notAfter : "");
      return;
    }

    if (st.storeError) {
      els.certQuickDot.className = "dot warn";
      els.certQuickText.textContent = "证书状态";
      els.certQuickBtn.title = "无法读取系统信任库，点击查看详情";
      els.certStatusBadge.className = "cert-badge";
      els.certStatusBadge.textContent = "信任状态未知";
      els.installCertBtn.textContent = "安装证书";
      els.certMetaText.textContent = "无法读取系统信任库：" + st.storeError;
      return;
    }

    if (st.burpReachable) {
      els.certQuickDot.className = "dot warn";
      els.certQuickText.textContent = "安装证书";
      els.certQuickBtn.title = "检测到 Burp 在线但本机尚未信任该根证书，点击一键安装";

      els.certStatusBadge.className = "cert-badge missing";
      els.certStatusBadge.textContent = "未安装";
      els.installCertBtn.textContent = "一键安装证书";
      els.certMetaText.textContent =
        "已连接 Burp (" +
        (st.burpAddr || "-") +
        ")，待导入 " +
        (st.commonName || "PortSwigger CA") +
        "（SHA-256 " +
        shortFingerprint(st.fingerprintSHA256) +
        "）。";
      return;
    }

    els.certQuickDot.className = "dot stopped";
    els.certQuickText.textContent = "安装证书";
    els.certQuickBtn.title = "请先启动 Burp 后点击一键安装根证书";

    els.certStatusBadge.className = "cert-badge";
    els.certStatusBadge.textContent =
      st.legacyCount > 0 ? "含历史证书 (" + st.legacyCount + ")" : "待连接 Burp";
    els.installCertBtn.textContent = "一键安装证书";
    els.certMetaText.textContent =
      "暂未连通 Burp (" +
      (st.burpAddr || "-") +
      ")，请先启动 Burp Listener 后再点击一键安装" +
      (st.legacyCount > 0 ? "；检测到本机已有 " + st.legacyCount + " 张历史 PortSwigger 证书，可随时点击卸载清理。" : "。");
  }

  async function fetchCertStatus() {
    try {
      const resp = await apiFetch("/api/cert/status");
      if (!resp.ok) return;
      applyCertStatus(await resp.json());
    } catch (_) {}
  }

  function applyCertActionStatus(data) {
    if (data.burpAddr && data.burpAddr === state.savedBurpAddr) {
      applyCertStatus(data);
    } else {
      fetchCertStatus();
    }
  }

  async function installBurpCert(fromSheet) {
    if (state.certBusy) return;
    state.certBusy = true;
    els.installCertBtn.disabled = true;
    els.certQuickBtn.disabled = true;

    try {
      const statusResp = await apiFetch("/api/cert/status");
      const current = await statusResp.json();
      if (!statusResp.ok) throw new Error(current.error || "证书状态读取失败");
      applyCertStatus(current);
      if (fromSheet && els.burpAddrInput.value.trim() !== current.burpAddr) {
        throw new Error("请先保存要使用的 Burp 地址");
      }
      if (!current.burpReachable || !current.fingerprintSHA256) {
        throw new Error(current.reachError || "无法读取当前 Burp CA 证书");
      }
      const scope = current.isAdmin ? "系统级信任库（可能对所有用户生效）" : "当前用户信任库";
      const confirmation =
        "Burp 地址：" + current.burpAddr +
        "\n证书：" + (current.subject || current.commonName) +
        "\nSHA-256：" + current.fingerprintSHA256 +
        "\n\n请与 Burp 中导出证书的指纹核对。确认将此证书添加到" + scope + "？";
      if (!window.confirm(confirmation)) return;
      const resp = await apiFetch("/api/cert/install", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          burpAddr: current.burpAddr,
          fingerprintSHA256: current.fingerprintSHA256,
        }),
      });
      const data = await resp.json();
      if (data.burpAddr) applyCertActionStatus(data);
      if (!resp.ok) throw new Error(data.error || "证书安装失败");
      const scopeDesc = formatScopeLabel(data.actionScope || data.installedScope);
      const okMsg = "已安装 " + data.burpAddr + " 的 Burp 根证书" + (scopeDesc ? "（" + scopeDesc + "）" : "");
      if (fromSheet) {
        showSheetFeedback(okMsg, false);
      } else {
        showToast(okMsg, false);
      }
    } catch (err) {
      if (fromSheet) {
        showSheetFeedback(err.message, true);
      } else {
        showToast(err.message, true);
      }
      fetchCertStatus();
    } finally {
      state.certBusy = false;
      els.installCertBtn.disabled = false;
      els.certQuickBtn.disabled = false;
    }
  }

  async function downloadBurpCert() {
    try {
      const resp = await apiFetch("/api/cert/download");
      if (!resp.ok) {
        const data = await resp.json();
        throw new Error(data.error || "证书下载失败");
      }
      const url = URL.createObjectURL(await resp.blob());
      const link = document.createElement("a");
      link.href = url;
      link.download = "burp-cacert.der";
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    } catch (err) {
      showSheetFeedback(err.message, true);
    }
  }

  async function uninstallBurpCert() {
    if (state.certBusy) return;
    state.certBusy = true;
    els.uninstallCertBtn.disabled = true;
    try {
      const resp = await apiFetch("/api/cert/uninstall", { method: "POST" });
      const data = await resp.json();
      applyCertActionStatus(data);
      const removed = data.removedCount > 0
        ? "已从系统根证书库移除 " + data.removedCount + " 张 Burp 证书"
        : "";
      const incomplete = resp.status === 409;
      const warning = data.warning || (incomplete ? data.error || "证书清理未完成" : "");
      const error = !resp.ok && !incomplete ? data.error || "卸载证书失败" : "";
      const message = [removed, error, warning].filter(Boolean).join("。");
      showSheetFeedback(message || "未发现需要移除的 Burp 根证书", Boolean(error), Boolean(warning));
    } catch (err) {
      showSheetFeedback(err.message, true);
      fetchCertStatus();
    } finally {
      state.certBusy = false;
      els.uninstallCertBtn.disabled = false;
    }
  }

  /* ------------------------------------------------------------------------
     Process Chips & ProxyBridge Lifecycle
     ------------------------------------------------------------------------ */

  function normalizeProcs(list) {
    const seen = new Set();
    const out = [];
    for (const raw of list) {
      let name = String(raw || "").trim();
      if (!name) continue;
      if (!name.toLowerCase().endsWith(".exe") && !name.includes(".") && !name.includes("*")) {
        name = name + ".exe";
      }
      const key = name.toLowerCase();
      if (!seen.has(key)) {
        seen.add(key);
        out.push(name);
      }
    }
    return out;
  }

  function formatProcessSubtitle(meta) {
    if (!meta) return "";
    const desc = (meta.description || "").trim();
    const win = (meta.windowTitle || "").trim();
    if (desc && win && desc.toLowerCase() !== win.toLowerCase() && !win.toLowerCase().includes(desc.toLowerCase())) {
      return desc + " · " + win;
    }
    return win || desc;
  }

  function syncSelectedProcsUI() {
    els.bridgeProcsInput.value = state.selectedProcs.join(", ");
    els.procAddInput.placeholder =
      state.selectedProcs.length > 0
        ? "继续添加进程..."
        : "输入目标进程名回车（如 client.exe）...";

    const frag = document.createDocumentFragment();
    for (const proc of state.selectedProcs) {
      const chip = document.createElement("span");
      chip.className = "chip-pill";

      const txt = document.createElement("span");
      txt.textContent = proc;
      chip.appendChild(txt);

      const meta = state.processMetaMap[proc.toLowerCase()];
      const subLabel = meta ? (meta.description || meta.windowTitle || "").trim() : "";
      if (subLabel) {
        const sub = document.createElement("span");
        sub.className = "chip-sub";
        sub.textContent = subLabel;
        chip.title = proc + " — " + formatProcessSubtitle(meta);
        chip.appendChild(sub);
      }

      const rm = document.createElement("button");
      rm.type = "button";
      rm.textContent = "×";
      rm.title = "移除 " + proc;
      rm.addEventListener("click", function () {
        state.processesEdited = true;
        state.selectedProcs = state.selectedProcs.filter(function (p) {
          return p.toLowerCase() !== proc.toLowerCase();
        });
        syncSelectedProcsUI();
        if (!els.procPickerDrawer.classList.contains("hidden")) {
          renderProcessPicker();
        }
      });
      chip.appendChild(rm);
      frag.appendChild(chip);
    }
    els.selectedProcsChips.replaceChildren(frag);
  }

  function addProcsFromText(raw) {
    const parts = raw.split(/[,，;；\s]+/).filter(Boolean);
    if (parts.length === 0) return;
    state.processesEdited = true;
    state.selectedProcs = normalizeProcs(state.selectedProcs.concat(parts));
    els.procAddInput.value = "";
    syncSelectedProcsUI();
    if (!els.procPickerDrawer.classList.contains("hidden")) {
      renderProcessPicker();
    }
  }

  function setTargetDomainStrategy(val) {
    state.targetDomains = val;
    els.targetDomainsSelect.value = val;
    for (const card of els.radioCards) {
      card.classList.toggle("active", card.dataset.domain === val);
    }
  }

  function renderLogs(logs) {
    const joined = logs.join("\n");
    if (joined === state.lastLogsText && els.engineLogsPre.childNodes.length > 0) {
      return;
    }
    state.lastLogsText = joined;
    els.copyLogsBtn.classList.toggle("hidden", logs.length === 0);

    const frag = document.createDocumentFragment();
    if (logs.length === 0) {
      const empty = document.createElement("div");
      empty.className = "log-empty";
      empty.textContent = "暂无引擎诊断日志输出";
      frag.appendChild(empty);
    } else {
      for (let i = 0; i < logs.length; i++) {
        const line = logs[i];
        const row = document.createElement("div");
        const lower = line.toLowerCase();
        const isErr = lower.includes("error") || lower.includes("fail") || lower.includes("denied");
        row.className = "log-row" + (isErr ? " is-err" : "");

        const ln = document.createElement("span");
        ln.className = "log-ln";
        ln.textContent = String(i + 1);

        const txt = document.createElement("span");
        txt.className = "log-txt";
        txt.textContent = line;

        row.appendChild(ln);
        row.appendChild(txt);
        frag.appendChild(row);
      }
    }
    els.engineLogsPre.replaceChildren(frag);
  }

  function syncBridgeButtons() {
    const canStop = state.bridgeState === "Running" || (state.bridgeState === "Error" && state.bridgePID > 0);
    els.bridgeStartBtn.disabled =
      state.bridgeRequestPending || state.bridgeState === "Starting" || state.bridgeIsAdmin === false;
    els.bridgeStopBtn.disabled = state.bridgeRequestPending || !canStop;
    els.bridgeStopBtn.classList.toggle("hidden", !canStop);
  }

  function applyBridgeStatus(st) {
    if (!st) return;
    state.bridgeState = st.state || "Stopped";
    state.bridgePID = Number(st.pid) || 0;
    if (typeof st.is_admin === "boolean") state.bridgeIsAdmin = st.is_admin;

    if (els.nonAdminWarning) {
      els.nonAdminWarning.classList.toggle("hidden", state.bridgeIsAdmin !== false);
    }

    if (st.state === "Running") {
      els.bridgeStatePill.className = "bridge-status running";
      els.bridgeDot.className = "dot running";
      els.bridgeStateText.textContent = "接管中 · PID " + st.pid;
      els.bridgeStartBtn.textContent = "更新重启";
    } else if (st.state === "Starting") {
      els.bridgeStatePill.className = "bridge-status";
      els.bridgeDot.className = "dot warn";
      els.bridgeStateText.textContent = "正在启动接管";
      els.bridgeStartBtn.textContent = "启动中…";
    } else if (st.state === "Error") {
      els.bridgeStatePill.className = "bridge-status error";
      els.bridgeDot.className = "dot error";
      els.bridgeStateText.textContent = "运行异常";
      els.bridgeStartBtn.textContent = "启动接管";
    } else {
      els.bridgeStatePill.className = "bridge-status";
      els.bridgeDot.className = "dot stopped";
      els.bridgeStateText.textContent = "未接管";
      els.bridgeStartBtn.textContent = "启动接管";
    }
    syncBridgeButtons();

    if (!state.bridgeHydrated) {
      const hasProcesses = Array.isArray(st.processes) && st.processes.length > 0;
      if (hasProcesses && !state.processesEdited) {
        state.selectedProcs = normalizeProcs(st.processes);
        syncSelectedProcsUI();
      }
      if (typeof st.targetDomains === "string" && !state.targetDomainsEdited) {
        setTargetDomainStrategy(st.targetDomains);
      }
      state.bridgeHydrated = hasProcesses || st.state === "Running";
    }

    if (st.lastError) {
      els.bridgeErrorBar.textContent = st.lastError;
      els.bridgeErrorBar.classList.remove("hidden");
    } else {
      els.bridgeErrorBar.textContent = "";
      els.bridgeErrorBar.classList.add("hidden");
    }

    els.bridgeBinDisplay.textContent = st.binaryPath || "";
    const logs = Array.isArray(st.logs) ? st.logs : [];
    els.logsCountBadge.textContent = String(logs.length);
    renderLogs(logs);
  }

  async function fetchBridgeStatus() {
    try {
      const resp = await apiFetch("/api/bridge/status");
      if (!resp.ok) return;
      applyBridgeStatus(await resp.json());
    } catch (_) {}
  }

  function ingestProcessData(data) {
    const rawItems = Array.isArray(data && data.items) ? data.items : null;
    const rawNames = Array.isArray(data && data.processes) ? data.processes : [];
    const items = rawItems
      ? rawItems.map(function (it) {
          return {
            name: String(it.name || ""),
            description: String(it.description || ""),
            windowTitle: String(it.windowTitle || ""),
            hasWindow: Boolean(it.hasWindow),
          };
        }).filter(function (it) { return Boolean(it.name); })
      : rawNames.map(function (n) {
          return { name: String(n), description: "", windowTitle: "", hasWindow: false };
        });

    state.runningProcesses = items;
    const nextMeta = Object.assign({}, state.processMetaMap);
    for (const it of items) {
      nextMeta[it.name.toLowerCase()] = it;
    }
    state.processMetaMap = nextMeta;
    syncSelectedProcsUI();
  }

  function renderProcessPicker() {
    const selectedSet = new Set(
      state.selectedProcs.map(function (p) { return p.toLowerCase(); })
    );
    const kw = state.procFilter.toLowerCase();
    const list = state.runningProcesses.filter(function (item) {
      if (!kw) return true;
      const hay = [item.name, item.description, item.windowTitle]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return hay.includes(kw);
    });

    els.procMatchCount.textContent = String(list.length);
    const frag = document.createDocumentFragment();

    if (list.length === 0) {
      const empty = document.createElement("div");
      empty.className = "popover-empty";
      empty.textContent = "未找到匹配的运行进程";
      frag.appendChild(empty);
    } else {
      for (const item of list) {
        const procName = item.name;
        const checked = selectedSet.has(procName.toLowerCase());
        const subtitle = formatProcessSubtitle(item);

        const row = document.createElement("label");
        row.className = "proc-row" + (checked ? " checked" : "");
        row.title = subtitle ? procName + " — " + subtitle : procName;

        const mainWrap = document.createElement("span");
        mainWrap.className = "proc-main";

        const cb = document.createElement("input");
        cb.type = "checkbox";
        cb.checked = checked;
        cb.addEventListener("change", function () {
          state.processesEdited = true;
          const rest = state.selectedProcs.filter(function (p) {
            return p.toLowerCase() !== procName.toLowerCase();
          });
          if (cb.checked) rest.push(procName);
          state.selectedProcs = normalizeProcs(rest);
          row.classList.toggle("checked", cb.checked);
          syncSelectedProcsUI();
        });

        const txt = document.createElement("span");
        txt.className = "proc-name";
        txt.textContent = procName;

        mainWrap.appendChild(cb);
        mainWrap.appendChild(txt);

        if (item.hasWindow) {
          const badge = document.createElement("span");
          badge.className = "proc-win-badge";
          badge.textContent = "窗口";
          mainWrap.appendChild(badge);
        }
        row.appendChild(mainWrap);

        if (subtitle) {
          const descSpan = document.createElement("span");
          descSpan.className = "proc-desc";
          descSpan.textContent = subtitle;
          row.appendChild(descSpan);
        }

        frag.appendChild(row);
      }
    }
    els.procCheckboxList.replaceChildren(frag);
  }

  async function refreshProcessMetaQuietly() {
    try {
      const resp = await apiFetch("/api/bridge/processes");
      if (!resp.ok) return;
      ingestProcessData(await resp.json());
    } catch (_) {}
  }

  async function toggleProcessPicker() {
    if (!els.procPickerDrawer.classList.contains("hidden")) {
      els.procPickerDrawer.classList.add("hidden");
      return;
    }
    els.refreshProcsBtn.disabled = true;
    try {
      const resp = await apiFetch("/api/bridge/processes");
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || "读取进程列表失败");
      ingestProcessData(data);
      els.procPickerDrawer.classList.remove("hidden");
      renderProcessPicker();
      els.procFilterInput.focus();
    } catch (err) {
      showToast(err.message, true);
    } finally {
      els.refreshProcsBtn.disabled = false;
    }
  }

  async function startBridge() {
    if (els.procAddInput.value.trim()) {
      addProcsFromText(els.procAddInput.value);
    }
    if (state.selectedProcs.length === 0) {
      showToast("请先输入或选择至少一个目标进程", true);
      els.procAddInput.focus();
      return;
    }
    state.bridgeHydrated = true;
    els.procPickerDrawer.classList.add("hidden");
    state.bridgeRequestPending = true;
    syncBridgeButtons();
    try {
      const resp = await apiFetch("/api/bridge/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          processes: state.selectedProcs,
          target_domains: state.targetDomains,
        }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || "启动失败");
      applyBridgeStatus(data);
      showToast("进程接管已启动", false);
    } catch (err) {
      showToast(err.message, true);
      fetchBridgeStatus();
    } finally {
      state.bridgeRequestPending = false;
      syncBridgeButtons();
    }
  }

  async function stopBridge() {
    state.bridgeRequestPending = true;
    syncBridgeButtons();
    try {
      const resp = await apiFetch("/api/bridge/stop", { method: "POST" });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || "停止失败");
      applyBridgeStatus(data);
      showToast("进程接管已停止", false);
    } catch (err) {
      showToast(err.message, true);
      fetchBridgeStatus();
    } finally {
      state.bridgeRequestPending = false;
      syncBridgeButtons();
    }
  }

  /* ------------------------------------------------------------------------
     Minimalist Connection Table Rendering
     ------------------------------------------------------------------------ */

  function formatTime(isoStr) {
    if (!isoStr) return "-";
    const d = new Date(isoStr);
    if (Number.isNaN(d.getTime())) return isoStr;
    const pad = function (n, len) {
      return String(n).padStart(len || 2, "0");
    };
    return (
      pad(d.getHours()) +
      ":" +
      pad(d.getMinutes()) +
      ":" +
      pad(d.getSeconds()) +
      "." +
      pad(d.getMilliseconds(), 3)
    );
  }

  function splitHostPort(target) {
    if (!target) return { host: "-", port: "" };
    const idx = target.lastIndexOf(":");
    if (idx <= 0) return { host: target, port: "" };
    const host = target.slice(0, idx);
    const port = target.slice(idx + 1);
    if (!/^\d+$/.test(port)) return { host: target, port: "" };
    return { host: host, port: port };
  }

  function isErrorRecord(rec) {
    return rec.status === "Error" || rec.action === "Rejected" || Boolean(rec.error);
  }

  function matchesFilter(rec) {
    if (state.actionFilter === "Burp" && rec.action !== "Burp") return false;
    if (state.actionFilter === "Direct" && rec.action !== "Direct") return false;
    if (state.actionFilter === "ERROR" && !isErrorRecord(rec)) return false;

    if (state.keyword) {
      const kw = state.keyword.toLowerCase();
      const hay = [rec.target, rec.protocol, rec.action, rec.status, rec.error]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      if (!hay.includes(kw)) return false;
    }
    return true;
  }

  function renderConnections() {
    const all = state.connections;
    let burpCount = 0;
    let directCount = 0;
    let errCount = 0;
    for (const rec of all) {
      if (rec.action === "Burp") burpCount++;
      else if (rec.action === "Direct") directCount++;
      if (isErrorRecord(rec)) errCount++;
    }

    els.countAll.textContent = String(all.length);
    els.countBurp.textContent = String(burpCount);
    els.countDirect.textContent = String(directCount);
    els.countError.textContent = String(errCount);
    els.capacityHint.textContent = all.length + " / " + state.capacity;

    const filtered = all.filter(matchesFilter);
    if (filtered.length === 0) {
      els.connTableBody.replaceChildren();
      els.emptyStatePanel.classList.remove("hidden");
      if (all.length === 0) {
        els.emptyTitle.textContent = "暂无连接记录";
        els.emptyDesc.classList.remove("hidden");
        els.resetFilterBtn.classList.add("hidden");
      } else {
        els.emptyTitle.textContent = "未找到匹配的连接";
        els.emptyDesc.classList.add("hidden");
        els.resetFilterBtn.classList.remove("hidden");
      }
      return;
    }

    els.emptyStatePanel.classList.add("hidden");
    const frag = document.createDocumentFragment();

    for (const rec of filtered) {
      const tr = document.createElement("tr");

      // 1. 时间
      const tdTime = document.createElement("td");
      tdTime.className = "col-time";
      tdTime.textContent = formatTime(rec.timestamp);
      tdTime.title = rec.timestamp || "";

      // 2. 目标 IP:端口
      const tdTarget = document.createElement("td");
      tdTarget.className = "col-target";
      const parts = splitHostPort(rec.target);
      const targetWrap = document.createElement("span");
      targetWrap.className = "target-wrap";
      targetWrap.title = (rec.target || "") + "（点击复制）";
      const hostSpan = document.createElement("span");
      hostSpan.className = "target-host";
      hostSpan.textContent = parts.host;
      targetWrap.appendChild(hostSpan);
      if (parts.port) {
        const portSpan = document.createElement("span");
        portSpan.className = "target-port";
        portSpan.textContent = ":" + parts.port;
        targetWrap.appendChild(portSpan);
      }
      targetWrap.addEventListener("click", async function () {
        if (rec.target && (await copyText(rec.target))) {
          showToast("已复制 " + rec.target, false);
        }
      });
      tdTarget.appendChild(targetWrap);

      // 3. 识别协议
      const tdProto = document.createElement("td");
      tdProto.className = "col-proto";
      const protoSpan = document.createElement("span");
      protoSpan.className = "proto-pill";
      protoSpan.textContent = rec.protocol || "-";
      tdProto.appendChild(protoSpan);

      // 4. 路由动作
      const tdAction = document.createElement("td");
      tdAction.className = "col-action";
      const actWrap = document.createElement("span");
      actWrap.className = "action-indicator";
      const actDot = document.createElement("span");
      const dotCls =
        rec.action === "Burp"
          ? "burp"
          : rec.action === "Direct"
          ? "direct"
          : "rejected";
      actDot.className = "action-dot " + dotCls;
      const actText = document.createElement("span");
      actText.textContent = rec.action || "-";
      actWrap.appendChild(actDot);
      actWrap.appendChild(actText);
      tdAction.appendChild(actWrap);

      // 5. 状态 / 错误信息
      const tdStatus = document.createElement("td");
      tdStatus.className = "col-status";
      const stWrap = document.createElement("div");
      stWrap.className = "status-wrap";
      const stLabel = document.createElement("span");
      if (rec.status === "Active") {
        stLabel.className = "status-label active";
        stLabel.textContent = "Active";
      } else if (rec.status === "Error") {
        stLabel.className = "status-label error";
        stLabel.textContent = "Error";
      } else {
        stLabel.className = "status-label";
        stLabel.textContent = rec.status || "Closed";
      }
      stWrap.appendChild(stLabel);

      if (rec.error) {
        const errDetail = document.createElement("span");
        errDetail.className = "status-err-detail";
        errDetail.textContent = rec.error;
        errDetail.title = rec.error;
        stWrap.appendChild(errDetail);
      }
      tdStatus.appendChild(stWrap);

      tr.appendChild(tdTime);
      tr.appendChild(tdTarget);
      tr.appendChild(tdProto);
      tr.appendChild(tdAction);
      tr.appendChild(tdStatus);
      frag.appendChild(tr);
    }

    els.connTableBody.replaceChildren(frag);
  }

  function applySnapshot(data) {
    if (!data) return;
    if (state.paused) {
      state.bufferedSnapshot = data;
      return;
    }
    state.connections = Array.isArray(data.connections) ? data.connections : [];
    if (data.capacity) state.capacity = data.capacity;
    renderConnections();
  }

  async function fetchConnectionsOnce() {
    try {
      const resp = await apiFetch("/api/connections");
      if (!resp.ok) return;
      applySnapshot(await resp.json());
    } catch (_) {}
  }

  function startFallbackPolling() {
    if (state.pollTimer) return;
    els.syncDot.className = "dot polling";
    els.syncText.textContent = "轮询同步中";
    fetchConnectionsOnce();
    state.pollTimer = window.setInterval(fetchConnectionsOnce, 1000);
  }

  function stopFallbackPolling() {
    if (state.pollTimer) {
      window.clearInterval(state.pollTimer);
      state.pollTimer = null;
    }
  }

  async function connectStream() {
    if (typeof window.ReadableStream === "undefined" || typeof window.TextDecoder === "undefined") {
      startFallbackPolling();
      return;
    }
    try {
      const resp = await apiFetch("/api/connections/stream");
      if (resp.status === 401) {
        stopFallbackPolling();
        showSessionError();
        return;
      }
      if (!resp.ok || !resp.body) throw new Error("连接流不可用");
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      const prefix = "event: connections\ndata: ";
      let buffer = "";
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          let boundary = buffer.indexOf("\n\n");
          while (boundary !== -1) {
            const event = buffer.slice(0, boundary);
            buffer = buffer.slice(boundary + 2);
            if (event.startsWith(prefix)) {
              applySnapshot(JSON.parse(event.slice(prefix.length)));
              stopFallbackPolling();
              els.syncDot.className = "dot online";
              els.syncText.textContent = "SSE 实时连接";
            }
            boundary = buffer.indexOf("\n\n");
          }
        }
      } finally {
        await reader.cancel();
      }
    } catch (_) {}
    startFallbackPolling();
    window.setTimeout(connectStream, 2000);
  }

  function showSessionError() {
    els.syncDot.className = "dot stopped";
    els.syncText.textContent = "控制台会话不可用";
    els.bridgeErrorBar.textContent = "控制台会话缺失或已过期。请在程序终端按 Enter 重新打开控制台，或输入 link 后按 Enter 获取链接。使用 -no-browser 启动时，终端会直接输出链接。";
    els.bridgeErrorBar.classList.remove("hidden");
  }

  /* ------------------------------------------------------------------------
     Event Listeners
     ------------------------------------------------------------------------ */

  els.themeToggleBtn.addEventListener("click", toggleTheme);

  els.openSettingsBtn.addEventListener("click", function () { openSheet("settings"); });
  els.summaryConfigBtn.addEventListener("click", function () { openSheet("settings"); });
  els.closeSettingsBtn.addEventListener("click", closeSheets);
  els.cancelSettingsBtn.addEventListener("click", closeSheets);

  els.certQuickBtn.addEventListener("click", function () {
    if (state.certStatus && (state.certStatus.installed || state.certStatus.storeError)) {
      openSheet("settings");
      return;
    }
    installBurpCert(false);
  });
  els.installCertBtn.addEventListener("click", function () {
    installBurpCert(true);
  });
  els.downloadCertBtn.addEventListener("click", downloadBurpCert);
  els.uninstallCertBtn.addEventListener("click", uninstallBurpCert);

  els.openLogsBtn.addEventListener("click", function () { openSheet("logs"); });
  els.closeLogsBtn.addEventListener("click", closeSheets);
  els.drawerBackdrop.addEventListener("click", closeSheets);

  els.copySocksBtn.addEventListener("click", async function () {
    const addr = els.socksAddrDisplay.textContent.trim();
    if (await copyText(addr)) {
      els.copySocksHint.textContent = "已复制";
      window.setTimeout(function () {
        els.copySocksHint.textContent = "复制";
      }, 1200);
    }
  });

  function switchMode(nextBypass) {
    if (nextBypass === state.bypassAll) return;
    updateConfig(
      { bypassAll: nextBypass },
      nextBypass ? "已切换为全局直连" : "已恢复智能分流",
      false
    );
  }

  els.modeSmartBtn.addEventListener("click", function () { switchMode(false); });
  els.modeBypassBtn.addEventListener("click", function () { switchMode(true); });
  els.restoreSmartBtn.addEventListener("click", function () { switchMode(false); });

  // Settings Sheet Events
  els.burpAddrInput.addEventListener("input", updateDirtyIndicator);
  els.directPortsInput.addEventListener("input", updateDirtyIndicator);

  els.portChipsEditor.addEventListener("click", function (ev) {
    if (ev.target === els.portChipsEditor || ev.target === els.portChipsList) {
      els.portAddInput.focus();
    }
  });

  els.portAddInput.addEventListener("keydown", function (ev) {
    if (ev.key === "Enter" || ev.key === ",") {
      ev.preventDefault();
      if (els.portAddInput.value.trim()) {
        addPortsFromEntry(els.portAddInput.value);
      } else if (ev.key === "Enter") {
        els.configForm.requestSubmit();
      }
    } else if (
      ev.key === "Backspace" &&
      !els.portAddInput.value &&
      state.portsList.length > 0
    ) {
      state.portsList = state.portsList.slice(0, -1);
      syncPortsUI();
    }
  });

  els.portAddInput.addEventListener("paste", function (ev) {
    const text = (ev.clipboardData || window.clipboardData).getData("text");
    if (text && /[\s,，;；]/.test(text)) {
      ev.preventDefault();
      addPortsFromEntry(text);
    }
  });

  els.portAddInput.addEventListener("blur", function () {
    if (els.portAddInput.value.trim()) {
      addPortsFromEntry(els.portAddInput.value);
    }
  });

  els.toggleRawPortsBtn.addEventListener("click", function () {
    if (!state.rawPortsMode) {
      state.rawPortsMode = true;
      els.directPortsInput.value = state.portsList.join(", ");
      els.portChipsEditor.classList.add("hidden");
      els.rawPortsEditor.classList.remove("hidden");
      els.toggleRawPortsBtn.textContent = "标签模式";
      els.directPortsInput.focus();
    } else {
      try {
        state.portsList = parsePortsString(els.directPortsInput.value);
        state.rawPortsMode = false;
        syncPortsUI();
        els.rawPortsEditor.classList.add("hidden");
        els.portChipsEditor.classList.remove("hidden");
        els.toggleRawPortsBtn.textContent = "文本模式";
      } catch (err) {
        showSheetFeedback(err.message, true);
      }
    }
  });

  els.resetDefaultPortsBtn.addEventListener("click", function () {
    state.portsList = DEFAULT_DIRECT_PORTS.slice();
    syncPortsUI();
    showSheetFeedback("已载入默认端口列表，点击保存生效", false);
  });

  for (const card of els.radioCards) {
    card.addEventListener("click", function () {
      state.targetDomainsEdited = true;
      setTargetDomainStrategy(card.dataset.domain || "");
    });
  }

  els.configForm.addEventListener("submit", function (ev) {
    ev.preventDefault();
    try {
      if (!state.rawPortsMode && !addPortsFromEntry(els.portAddInput.value)) {
        return;
      }
      const burpAddr = els.burpAddrInput.value.trim();
      const directPorts = state.rawPortsMode
        ? parsePortsString(els.directPortsInput.value)
        : state.portsList.slice();
      state.portsList = directPorts;
      syncPortsUI();
      updateConfig(
        { burpAddr: burpAddr, directPorts: directPorts },
        "设置已保存并立即生效",
        true
      );
    } catch (err) {
      showSheetFeedback(err.message, true);
    }
  });

  // Process Intercept Bar Events
  els.procAddInput.addEventListener("keydown", function (ev) {
    if (ev.key === "Enter" || ev.key === ",") {
      ev.preventDefault();
      addProcsFromText(els.procAddInput.value);
    } else if (
      ev.key === "Backspace" &&
      !els.procAddInput.value &&
      state.selectedProcs.length > 0
    ) {
      state.processesEdited = true;
      state.selectedProcs = state.selectedProcs.slice(0, -1);
      syncSelectedProcsUI();
      if (!els.procPickerDrawer.classList.contains("hidden")) {
        renderProcessPicker();
      }
    }
  });

  els.procAddInput.addEventListener("blur", function () {
    if (els.procAddInput.value.trim()) {
      addProcsFromText(els.procAddInput.value);
    }
  });

  els.refreshProcsBtn.addEventListener("click", toggleProcessPicker);
  els.closePickerBtn.addEventListener("click", function () {
    els.procPickerDrawer.classList.add("hidden");
  });

  els.procFilterInput.addEventListener("input", function () {
    state.procFilter = els.procFilterInput.value.trim();
    renderProcessPicker();
  });

  // Click outside to close process popover
  document.addEventListener("mousedown", function (ev) {
    if (
      !els.procPickerDrawer.classList.contains("hidden") &&
      !els.procInputArea.contains(ev.target)
    ) {
      els.procPickerDrawer.classList.add("hidden");
    }
  });

  els.bridgeStartBtn.addEventListener("click", startBridge);
  els.bridgeStopBtn.addEventListener("click", stopBridge);

  // Logs Sheet Actions
  els.refreshLogsBtn.addEventListener("click", fetchBridgeStatus);
  els.copyLogsBtn.addEventListener("click", async function () {
    if (await copyText(state.lastLogsText)) {
      showToast("日志已复制", false);
    }
  });

  // Table Filters & Search
  for (const tab of els.filterTabs) {
    tab.addEventListener("click", function () {
      state.actionFilter = tab.dataset.filter || "ALL";
      for (const t of els.filterTabs) {
        const active = t === tab;
        t.classList.toggle("active", active);
        t.setAttribute("aria-selected", String(active));
      }
      renderConnections();
    });
  }

  els.keywordInput.addEventListener("input", function () {
    state.keyword = els.keywordInput.value.trim();
    els.searchSlashHint.classList.toggle("hidden", Boolean(state.keyword));
    renderConnections();
  });

  els.resetFilterBtn.addEventListener("click", function () {
    state.actionFilter = "ALL";
    state.keyword = "";
    els.keywordInput.value = "";
    els.searchSlashHint.classList.remove("hidden");
    for (const t of els.filterTabs) {
      const isAll = t.dataset.filter === "ALL";
      t.classList.toggle("active", isAll);
      t.setAttribute("aria-selected", String(isAll));
    }
    renderConnections();
  });

  els.pauseStreamBtn.addEventListener("click", function () {
    state.paused = !state.paused;
    els.pauseStreamBtn.classList.toggle("paused", state.paused);
    els.pauseStreamBtn.textContent = state.paused ? "继续" : "暂停";
    if (!state.paused && state.bufferedSnapshot) {
      const snap = state.bufferedSnapshot;
      state.bufferedSnapshot = null;
      applySnapshot(snap);
    }
  });

  els.clearBtn.addEventListener("click", async function () {
    try {
      const resp = await apiFetch("/api/connections/clear", { method: "POST" });
      if (resp.ok) {
        state.connections = [];
        state.bufferedSnapshot = null;
        renderConnections();
      }
    } catch (_) {}
  });

  // Keyboard shortcuts: '/' for search, 'Escape' to close sheets/popovers
  document.addEventListener("keydown", function (ev) {
    if (ev.key === "Escape") {
      if (state.activeSheet) {
        closeSheets();
      } else if (!els.procPickerDrawer.classList.contains("hidden")) {
        els.procPickerDrawer.classList.add("hidden");
      }
      return;
    }
    if (
      ev.key === "/" &&
      !state.activeSheet &&
      document.activeElement &&
      !["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement.tagName)
    ) {
      ev.preventDefault();
      els.keywordInput.focus();
    }
  });

  /* ------------------------------------------------------------------------
     Init
     ------------------------------------------------------------------------ */

  initTheme();
  state.sessionToken = loadSessionToken();
  if (state.sessionToken) {
    loadConfig().then(function (loaded) {
      if (!loaded) return;
      fetchBridgeStatus();
      fetchCertStatus();
      refreshProcessMetaQuietly();
      window.setInterval(fetchBridgeStatus, 2000);
      connectStream();
    });
  } else {
    showSessionError();
  }
})();
