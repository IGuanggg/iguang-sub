(() => {
  const toast = document.getElementById("toast");
  const showToast = (message) => {
    if (!toast) return;
    toast.textContent = message;
    toast.classList.add("show");
    setTimeout(() => toast.classList.remove("show"), 1300);
  };

  document.addEventListener("click", async (event) => {
    const copyButton = event.target.closest("[data-copy]");
    if (copyButton) {
      try {
        await navigator.clipboard.writeText(copyButton.dataset.copy || "");
        showToast("已复制");
      } catch (_error) {
        showToast("复制失败");
      }
    }

    const toggle = event.target.closest("[data-menu-toggle]");
    if (toggle) {
      document.querySelector(".sidebar")?.classList.toggle("open");
    }

    const upstreamEditToggle = event.target.closest("[data-upstream-edit-toggle]");
    if (upstreamEditToggle) {
      const id = upstreamEditToggle.dataset.upstreamEditToggle;
      const dialog = document.querySelector(`[data-upstream-editor="${id}"]`);
      if (dialog?.showModal) {
        dialog.showModal();
        upstreamEditToggle.setAttribute("aria-expanded", "true");
        dialog.querySelector('input[name="url"]')?.focus();
      }
    }

    const upstreamEditClose = event.target.closest("[data-upstream-edit-close]");
    if (upstreamEditClose) {
      const id = upstreamEditClose.dataset.upstreamEditClose;
      document.querySelector(`[data-upstream-editor="${id}"]`)?.close();
      document.querySelector(`[data-upstream-edit-toggle="${id}"]`)?.setAttribute("aria-expanded", "false");
    }

    const accountToggle = event.target.closest("[data-account-toggle]");
    if (accountToggle) {
      const menu = accountToggle.closest("[data-account-menu]");
      const popover = menu?.querySelector("[data-account-popover]");
      const isOpen = popover?.classList.toggle("open");
      accountToggle.setAttribute("aria-expanded", isOpen ? "true" : "false");
    } else if (!event.target.closest("[data-account-menu]")) {
      document.querySelectorAll("[data-account-popover].open").forEach((popover) => popover.classList.remove("open"));
      document.querySelectorAll("[data-account-toggle][aria-expanded='true']").forEach((button) => button.setAttribute("aria-expanded", "false"));
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "/" && searchInput && !event.ctrlKey && !event.metaKey && !event.altKey) {
      const tag = event.target?.tagName?.toLowerCase();
      if (!["input", "textarea", "select"].includes(tag)) {
        event.preventDefault();
        searchInput.focus();
      }
    }
    if (event.key === "Escape") {
      document.querySelector(".sidebar")?.classList.remove("open");
      document.querySelectorAll("[data-account-popover].open").forEach((popover) => popover.classList.remove("open"));
      document.querySelectorAll("[data-account-toggle][aria-expanded='true']").forEach((button) => button.setAttribute("aria-expanded", "false"));
    }
  });

  document.querySelectorAll("form[data-auto-submit] select").forEach((select) => {
    select.addEventListener("change", () => select.form?.requestSubmit());
  });

  const searchForm = document.querySelector("[data-global-search]");
  const searchInput = searchForm?.querySelector('input[name="q"]');
  const searchPopover = searchForm?.querySelector("[data-search-popover]");
  let searchTimer = null;

  const renderSearch = (payload) => {
    if (!searchPopover) return;
    const groups = payload?.groups || {};
    const escapeHtml = (value) => String(value || "").replace(/[&<>"']/g, (char) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    }[char]));
    const safeHref = (value) => {
      const href = String(value || "#");
      return href.startsWith("/") ? href : "#";
    };
    const blocks = Object.entries(groups).map(([key, items]) => {
      if (!items || !items.length) return "";
      const title = key === "nodes" ? "节点" : key === "upstreams" ? "上游订阅" : key === "users" ? "用户" : key === "events" ? "流量事件" : "审计日志";
      return `<section><strong>${title}</strong>${items.map((item) => `<a href="${safeHref(item.href)}"><b>${escapeHtml(item.title)}</b><small>${escapeHtml(item.meta)}</small></a>`).join("")}</section>`;
    }).filter(Boolean).join("");
    searchPopover.innerHTML = blocks || '<div class="search-empty">没有匹配项</div>';
    searchPopover.classList.toggle("open", Boolean(payload?.q));
  };

  const hideSearch = () => searchPopover?.classList.remove("open");

  searchInput?.addEventListener("input", () => {
    clearTimeout(searchTimer);
    const q = (searchInput.value || "").trim();
    if (!q) {
      hideSearch();
      return;
    }
    searchTimer = setTimeout(async () => {
      try {
        const resp = await fetch(`/admin/search.json?q=${encodeURIComponent(q)}`, { headers: { Accept: "application/json" } });
        if (!resp.ok) return;
        renderSearch(await resp.json());
      } catch (_error) {
        hideSearch();
      }
    }, 180);
  });

  searchInput?.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      hideSearch();
      searchInput.blur();
    }
  });

  document.addEventListener("click", (event) => {
    if (!searchForm?.contains(event.target)) hideSearch();
  });

  document.querySelectorAll(".upstream-edit-dialog").forEach((dialog) => {
    dialog.addEventListener("close", () => {
      document.querySelector(`[data-upstream-edit-toggle="${dialog.dataset.upstreamEditor}"]`)?.setAttribute("aria-expanded", "false");
    });
    dialog.addEventListener("click", (event) => {
      if (event.target === dialog) dialog.close();
    });
  });

  const statusPool = document.querySelector("[data-nodes-status-pool]");
  if (statusPool) {
    const setText = (name, value) => {
      statusPool.querySelectorAll(`[data-status-field="${name}"]`).forEach((el) => {
        el.textContent = value ?? "";
      });
    };
    const setBar = (name, value) => {
      const width = Math.max(0, Math.min(100, Number(value) || 0));
      statusPool.querySelectorAll(`[data-status-bar="${name}"]`).forEach((el) => {
        el.style.width = `${width}%`;
      });
    };
    const setCardTone = (field, tone) => {
      const node = statusPool.querySelector(`[data-status-field="${field}"]`)?.closest(".subs-control-card, .console-verdict, .pool-flow article");
      if (!node) return;
      node.classList.remove("ok", "warn", "danger");
      node.classList.add(tone);
    };
    const refreshNodeStatus = async () => {
      const url = statusPool.dataset.statusUrl;
      if (!url) return;
      try {
        const resp = await fetch(url, { headers: { Accept: "application/json" }, cache: "no-store" });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const payload = await resp.json();
        const engine = payload.engine || {};
        const assets = payload.assets || {};
        const subs = payload.subs_check || {};
        const api = payload.api || {};
        const quality = engine.quality || subs.quality || {};
        const engineLabel = engine.active_label || (engine.active === "subs-check" ? "优选输出" : "全量输出");
        setText("default_output_label", engine.default_output_label || "-");
        setText("engine_pill", `${engineLabel} · ${engine.default_output_count || 0} 个`);
        setText("default_output_count", engine.default_output_count ?? 0);
        setText("engine_reason", engine.reason || "-");
        setText("status_detail", engine.status_detail || "-");
        setText("asset_pool_count", engine.asset_pool_count ?? assets.total ?? 0);
        setText("asset_total", assets.total ?? engine.asset_pool_count ?? 0);
        setText("filtered_count", assets.filtered ?? 0);
        setText("upstream_total", assets.upstream_total ?? 0);
        setText("upstream_filtered", assets.upstream_filtered ?? 0);
        setText("proxy_ok", assets.proxy_ok ?? 0);
        setText("subscription_count", assets.subscription_count ?? engine.default_output_count ?? 0);
        setText("subs_count", subs.node_count ?? 0);
        setText("subs_message", `阈值 ${engine.min_output_nodes || 0} · ${subs.message || "-"}`);
        setText("quality_current_l3", quality.current_l3 ?? 0);
        setText("quality_stable_3", quality.stable_3 ?? 0);
        setText("quality_intermittent_2", quality.intermittent_2 ?? 0);
        setText("quality_match_percent", `${quality.match_percent || 0}%`);
        setText("quality_match_detail", `${quality.matched_output_count || 0}/${quality.output_count || 0} · ${quality.checked_label || "暂无轮次"}`);
        setText("check_label", api.label || "未知");
        setText("check_progress", `进度 ${api.progress || 0}/${api.proxy_count || 0} · 通过 ${api.available || 0}`);
        setText("checked_label", payload.checked_label || "刚刚");
        setText("alive_percent", `${api.alive_percent || 0}%`);
        setText("available_percent", `${api.available_percent || 0}%`);
        setText("speed_percent", `${api.speed_percent || 0}%`);
        setBar("alive", api.alive_percent);
        setBar("available", api.available_percent);
        setBar("speed", api.speed_percent);
        statusPool.classList.toggle("is-checking", Boolean(api.checking));
        const pill = statusPool.querySelector(".engine-pill");
        if (pill) {
          pill.classList.remove("ok", "warn", "danger", "neutral");
          pill.classList.add(engine.status_tone || "warn");
        }
        setCardTone("default_output_count", engine.status_tone || "warn");
        setCardTone("subs_count", subs.ok ? "ok" : "danger");
        setCardTone("check_label", api.checking ? "warn" : api.ok ? "ok" : "danger");
      } catch (_error) {
        setText("checked_label", "状态读取失败");
      }
    };

    statusPool.querySelectorAll("form").forEach((form) => {
      form.addEventListener("submit", () => {
        showToast("操作已提交，状态池会自动刷新");
      });
    });
    refreshNodeStatus();
    setInterval(refreshNodeStatus, 8000);
  }
})();
