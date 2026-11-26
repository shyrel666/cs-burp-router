// Process Selection & Active Outbound Discovery ES Module

export function normalizeProcs(list) {
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

export function formatProcessSubtitle(meta) {
  if (!meta) return "";
  const desc = (meta.description || "").trim();
  const win = (meta.windowTitle || "").trim();
  if (
    desc &&
    win &&
    desc.toLowerCase() !== win.toLowerCase() &&
    !win.toLowerCase().includes(desc.toLowerCase())
  ) {
    return desc + " · " + win;
  }
  return win || desc;
}

export function createProcessController({ state, els, apiFetch, showToast }) {
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

  function ingestProcessData(data) {
    const rawItems = Array.isArray(data && data.items) ? data.items : null;
    const rawNames = Array.isArray(data && data.processes) ? data.processes : [];
    const items = rawItems
      ? rawItems
          .map(function (it) {
            const rawSamples = Array.isArray(it.sample_targets) ? it.sample_targets : [];
            return {
              name: String(it.name || ""),
              description: String(it.description || ""),
              windowTitle: String(it.windowTitle || ""),
              hasWindow: Boolean(it.hasWindow),
              activeConnections: Number(it.active_connections || 0),
              sampleTargets: rawSamples.map(String).filter(Boolean),
            };
          })
          .filter(function (it) {
            return Boolean(it.name);
          })
      : rawNames.map(function (n) {
          return {
            name: String(n),
            description: "",
            windowTitle: "",
            hasWindow: false,
            activeConnections: 0,
            sampleTargets: [],
          };
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
      state.selectedProcs.map(function (p) {
        return p.toLowerCase();
      })
    );
    const kw = state.procFilter.toLowerCase();
    const totalActive = state.runningProcesses.filter(function (it) {
      return it.activeConnections > 0;
    }).length;

    if (els.activeProcsHint) {
      els.activeProcsHint.textContent = "活跃外联 " + totalActive + " / 共 " + state.runningProcesses.length;
    }

    const list = state.runningProcesses.filter(function (item) {
      if (state.onlyActiveOutbound && item.activeConnections <= 0) {
        return false;
      }
      if (!kw) return true;
      const hay = [
        item.name,
        item.description,
        item.windowTitle,
        item.sampleTargets.join(" "),
      ]
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
      empty.textContent = state.onlyActiveOutbound
        ? "当前暂无匹配的外联 TCP 进程"
        : "未找到匹配的运行进程";
      frag.appendChild(empty);
    } else {
      for (const item of list) {
        const procName = item.name;
        const checked = selectedSet.has(procName.toLowerCase());
        const subtitle = formatProcessSubtitle(item);
        const hasActive = item.activeConnections > 0;

        const row = document.createElement("label");
        row.className = "proc-row" + (checked ? " checked" : "") + (hasActive ? " has-active" : "");

        const tooltipParts = [procName];
        if (hasActive) {
          tooltipParts.push("外联连接 (" + item.activeConnections + "): " + item.sampleTargets.join(", "));
        }
        if (subtitle) {
          tooltipParts.push(subtitle);
        }
        row.title = tooltipParts.join(" — ");

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

        if (hasActive) {
          const connBadge = document.createElement("span");
          connBadge.className = "proc-conn-badge";
          connBadge.textContent = "(" + item.activeConnections + ")";
          mainWrap.appendChild(connBadge);
        } else if (item.hasWindow) {
          const badge = document.createElement("span");
          badge.className = "proc-win-badge";
          badge.textContent = "窗口";
          mainWrap.appendChild(badge);
        }
        row.appendChild(mainWrap);

        if (hasActive && item.sampleTargets.length > 0) {
          const targetSpan = document.createElement("span");
          targetSpan.className = "proc-target-preview mono";
          const more = item.sampleTargets.length > 1 ? " +" + (item.sampleTargets.length - 1) : "";
          targetSpan.textContent = "→ " + item.sampleTargets[0] + more;
          row.appendChild(targetSpan);
        } else if (subtitle) {
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

  async function reloadProcessPicker() {
    if (els.reloadProcsBtn) els.reloadProcsBtn.disabled = true;
    els.refreshProcsBtn.disabled = true;
    try {
      const resp = await apiFetch("/api/bridge/processes");
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || "读取进程列表失败");
      ingestProcessData(data);
      renderProcessPicker();
    } catch (err) {
      showToast(err.message, true);
    } finally {
      if (els.reloadProcsBtn) els.reloadProcsBtn.disabled = false;
      els.refreshProcsBtn.disabled = false;
    }
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

  // Bind Process Input & Picker Events
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
  if (els.reloadProcsBtn) {
    els.reloadProcsBtn.addEventListener("click", reloadProcessPicker);
  }
  els.closePickerBtn.addEventListener("click", function () {
    els.procPickerDrawer.classList.add("hidden");
  });

  els.procFilterInput.addEventListener("input", function () {
    state.procFilter = els.procFilterInput.value.trim();
    renderProcessPicker();
  });

  if (els.onlyActiveOutboundToggle) {
    els.onlyActiveOutboundToggle.addEventListener("change", function () {
      state.onlyActiveOutbound = Boolean(els.onlyActiveOutboundToggle.checked);
      renderProcessPicker();
    });
  }

  document.addEventListener("mousedown", function (ev) {
    if (
      !els.procPickerDrawer.classList.contains("hidden") &&
      !els.procInputArea.contains(ev.target)
    ) {
      els.procPickerDrawer.classList.add("hidden");
    }
  });

  return {
    syncSelectedProcsUI,
    addProcsFromText,
    ingestProcessData,
    renderProcessPicker,
    refreshProcessMetaQuietly,
    toggleProcessPicker,
  };
}
