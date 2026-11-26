// Per-Target Route Overrides (Pinning) ES Module

function normalizeHost(raw) {
  let h = String(raw || "").trim();
  while (h.endsWith(".")) {
    h = h.slice(0, -1);
  }
  return h.toLowerCase();
}

export function splitTargetHostPort(target) {
  const raw = String(target || "").trim();
  if (!raw) return { host: "", port: "" };

  // Bracketed IPv6: [::1]:443 or [::1]
  if (raw.startsWith("[")) {
    const closeIdx = raw.indexOf("]");
    if (closeIdx > 1) {
      const host = raw.slice(1, closeIdx);
      const rest = raw.slice(closeIdx + 1);
      if (rest.startsWith(":") && /^\d+$/.test(rest.slice(1))) {
        return { host, port: rest.slice(1) };
      }
      return { host, port: "" };
    }
  }

  const firstColon = raw.indexOf(":");
  const lastColon = raw.lastIndexOf(":");
  if (firstColon !== -1 && firstColon === lastColon) {
    const host = raw.slice(0, lastColon);
    const port = raw.slice(lastColon + 1);
    if (/^\d+$/.test(port)) {
      return { host, port };
    }
  }
  return { host: raw, port: "" };
}

export function normalizeTargetKey(target) {
  const { host, port } = splitTargetHostPort(target);
  const normHost = normalizeHost(host);
  if (!normHost) return "";
  if (!port) return normHost;
  if (normHost.includes(":")) {
    return "[" + normHost + "]:" + port;
  }
  return normHost + ":" + port;
}

export function createOverridesController({ apiFetch, showToast, onChanged, els }) {
  let rules = [];
  let ruleMap = new Map();
  let busyTargets = new Set();

  function rebuildMap(list) {
    rules = Array.isArray(list) ? list : [];
    ruleMap = new Map();
    for (const rule of rules) {
      if (!rule || !rule.target) continue;
      ruleMap.set(normalizeTargetKey(rule.target), rule);
    }
  }

  function findMatch(target) {
    const exactKey = normalizeTargetKey(target);
    if (!exactKey) return null;
    if (ruleMap.has(exactKey)) {
      return { rule: ruleMap.get(exactKey), matchType: "exact" };
    }
    const { host } = splitTargetHostPort(target);
    const hostKey = normalizeHost(host);
    if (hostKey && ruleMap.has(hostKey)) {
      return { rule: ruleMap.get(hostKey), matchType: "host" };
    }
    return null;
  }

  function renderSettingsList() {
    if (!els.overridesChipsList) return;
    if (els.overridesCountBadge) {
      els.overridesCountBadge.textContent = String(rules.length);
    }
    if (els.clearOverridesBtn) {
      els.clearOverridesBtn.classList.toggle("hidden", rules.length === 0);
    }
    if (els.overridesEmptyHint) {
      els.overridesEmptyHint.classList.toggle("hidden", rules.length > 0);
    }

    const frag = document.createDocumentFragment();
    for (const rule of rules) {
      const chip = document.createElement("span");
      const actCls = rule.action === "Burp" ? "burp" : "direct";
      chip.className = "override-chip " + actCls;

      const dot = document.createElement("span");
      dot.className = "action-dot " + actCls;
      chip.appendChild(dot);

      const targetSpan = document.createElement("span");
      targetSpan.className = "override-chip-target mono";
      targetSpan.textContent = rule.target;
      targetSpan.title = rule.target;
      chip.appendChild(targetSpan);

      const actSpan = document.createElement("span");
      actSpan.className = "override-chip-action";
      actSpan.textContent = rule.action === "Burp" ? "进 Burp" : "直连";
      chip.appendChild(actSpan);

      const rmBtn = document.createElement("button");
      rmBtn.type = "button";
      rmBtn.className = "override-chip-rm";
      rmBtn.textContent = "×";
      rmBtn.title = "删除覆盖规则 " + rule.target;
      rmBtn.addEventListener("click", function () {
        deleteOverride(rule.target);
      });
      chip.appendChild(rmBtn);

      frag.appendChild(chip);
    }
    els.overridesChipsList.replaceChildren(frag);
  }

  function applyOverrides(list) {
    rebuildMap(list);
    renderSettingsList();
    if (typeof onChanged === "function") {
      onChanged(rules);
    }
  }

  async function fetchOverrides() {
    try {
      const resp = await apiFetch("/api/overrides");
      if (!resp.ok) return;
      const data = await resp.json();
      applyOverrides(data && data.overrides);
    } catch (_) {}
  }

  async function setOverride(target, action) {
    const key = normalizeTargetKey(target);
    if (!key || busyTargets.has(key)) return;
    busyTargets.add(key);
    try {
      const resp = await apiFetch("/api/overrides", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, action }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || "设置覆盖规则失败");
      applyOverrides(data.overrides);
      const label = action === "Burp" ? "强制进 Burp" : "强制直连";
      showToast("已覆盖 " + (data.rule ? data.rule.target : target) + " → " + label, false);
    } catch (err) {
      showToast(err.message, true);
    } finally {
      busyTargets.delete(key);
    }
  }

  async function deleteOverride(target) {
    const key = normalizeTargetKey(target);
    if (!key || busyTargets.has(key)) return;
    busyTargets.add(key);
    try {
      const resp = await apiFetch("/api/overrides?target=" + encodeURIComponent(target), {
        method: "DELETE",
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || "取消覆盖失败");
      applyOverrides(data.overrides);
      showToast("已取消覆盖 " + target, false);
    } catch (err) {
      showToast(err.message, true);
    } finally {
      busyTargets.delete(key);
    }
  }

  async function clearOverrides() {
    if (rules.length === 0) return;
    try {
      const resp = await apiFetch("/api/overrides", { method: "DELETE" });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || "清空覆盖规则失败");
      applyOverrides(data.overrides);
      showToast("已清空全部覆盖规则", false);
    } catch (err) {
      showToast(err.message, true);
    }
  }

  function createRowControls(rec) {
    const wrap = document.createElement("div");
    wrap.className = "ops-wrap";

    if (!rec || !rec.target) {
      const empty = document.createElement("span");
      empty.className = "ops-muted";
      empty.textContent = "-";
      wrap.appendChild(empty);
      return wrap;
    }

    if (rec.protocol === "Loopback" || rec.action === "Rejected") {
      const protectedTag = document.createElement("span");
      protectedTag.className = "ops-muted";
      protectedTag.textContent = "回环保护";
      wrap.appendChild(protectedTag);
      return wrap;
    }

    const matched = findMatch(rec.target);
    if (matched) {
      const rule = matched.rule;
      const isBurp = rule.action === "Burp";
      const tag = document.createElement("span");
      tag.className = "override-tag " + (isBurp ? "burp" : "direct");
      tag.textContent = isBurp ? "已强制进 Burp" : "已强制直连";
      tag.title = "命中规则: " + rule.target + " → " + rule.action;

      const cancelBtn = document.createElement("button");
      cancelBtn.type = "button";
      cancelBtn.className = "op-btn clear";
      cancelBtn.textContent = "取消覆盖";
      cancelBtn.title = "移除覆盖规则 " + rule.target;
      cancelBtn.addEventListener("click", function () {
        deleteOverride(rule.target);
      });

      wrap.appendChild(tag);
      wrap.appendChild(cancelBtn);
      return wrap;
    }

    const directBtn = document.createElement("button");
    directBtn.type = "button";
    directBtn.className = "op-btn direct";
    directBtn.textContent = "强制直连";
    directBtn.title = "将 " + rec.target + " 设为强制直连（跳过 200ms 窥探）";
    directBtn.addEventListener("click", function () {
      setOverride(rec.target, "Direct");
    });

    const burpBtn = document.createElement("button");
    burpBtn.type = "button";
    burpBtn.className = "op-btn burp";
    burpBtn.textContent = "强制进 Burp";
    burpBtn.title = "将 " + rec.target + " 强制转发至 Burp（突破端口白名单）";
    burpBtn.addEventListener("click", function () {
      setOverride(rec.target, "Burp");
    });

    wrap.appendChild(directBtn);
    wrap.appendChild(burpBtn);
    return wrap;
  }

  if (els.clearOverridesBtn) {
    els.clearOverridesBtn.addEventListener("click", clearOverrides);
  }

  return {
    fetchOverrides,
    setOverride,
    deleteOverride,
    clearOverrides,
    findMatch,
    createRowControls,
    renderSettingsList,
    getRules: function () {
      return rules.slice();
    },
  };
}
