// ============================================================
// DSH Security Guard - client bundle (shield button + risk popup)
// Loaded by DSH web UI automatically because package.json declares
// dsh.client.platform = "web" and exports["./client"].
// It injects a shield button into the conversation input left slot,
// polls the local SecurityGuard API for critical alerts and shows a
// popup with "handle / keep" actions when new issues are found.
// ============================================================

window.__ModuleLoader__.load({
  id: "dsh-security-guard",
  factory: (require) => {
    var module = { exports: {} };
    var exports = module.exports;
    Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });
    let react = require("react");

    // ---- styles ----
    const css = [
      ".sg-shield{display:inline-flex;align-items:center;gap:5px;height:28px;padding:0 10px;border:none;cursor:pointer;font-size:12px;font-weight:600;color:#fff;background:linear-gradient(135deg,#2ea043,#1b5e20);border-radius:6px;transition:filter .15s,transform .15s}",
      ".sg-shield:hover{filter:brightness(1.12)}",
      ".sg-shield:active{transform:translateY(1px)}",
      ".sg-shield-icon{width:20px;height:20px;display:inline-flex;align-items:center;justify-content:center;background:rgba(255,255,255,.18);clip-path:polygon(50% 0,100% 18%,100% 72%,50% 100%,0 72%,0 18%);font-size:11px;line-height:1}",
      ".sg-shield-text{white-space:nowrap}",
      ".sg-modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:99999;display:flex;align-items:center;justify-content:center;padding:20px}",
      ".sg-modal{background:#161b22;border:1px solid #30363d;border-radius:12px;max-width:560px;width:100%;max-height:80vh;overflow:auto;box-shadow:0 12px 40px rgba(0,0,0,.5);color:#c9d1d9;font-size:13px}",
      ".sg-modal-head{padding:14px 16px;border-bottom:1px solid #30363d;display:flex;align-items:center;gap:10px;font-size:15px;font-weight:600;color:#fff}",
      ".sg-modal-body{padding:14px 16px}",
      ".sg-modal-msg{color:#f85149;font-weight:600;margin-bottom:10px}",
      ".sg-finding{display:flex;flex-direction:column;gap:4px;padding:8px 10px;border:1px solid #30363d;border-radius:8px;margin-bottom:8px;background:#0d1117}",
      ".sg-finding-title{display:flex;align-items:center;gap:8px;flex-wrap:wrap}",
      ".sg-finding-rec{color:#8b949e;font-size:12px}",
      ".sg-modal-foot{padding:12px 16px;border-top:1px solid #30363d;display:flex;gap:10px;justify-content:flex-end}",
      ".sg-btn{border-radius:6px;border:1px solid #30363d;background:#21262d;color:#c9d1d9;padding:6px 14px;cursor:pointer;font-size:12px}",
      ".sg-btn:hover{background:#30363d}",
      ".sg-btn-primary{background:#238636;border-color:#238636;color:#fff}",
      ".sg-btn-primary:hover{background:#2ea043}",
      ".sg-btn-danger{background:#da3633;border-color:#da3633;color:#fff}",
      ".sg-btn-danger:hover{background:#f85149}",
    ].join("");
    const tagId = "dsh-security-guard/shield.css";
    if (typeof document !== "undefined" && document.querySelector("style[data-plugin-css=\"" + tagId + "\"]") === null) {
      const tag = document.createElement("style");
      tag.dataset.plugin = "dsh-security-guard";
      tag.dataset.pluginCss = tagId;
      tag.textContent = css;
      document.head.appendChild(tag);
    }

    function openDashboard() {
      const url = "/security-guard";
      try {
        const a = document.createElement("a");
        a.href = url;
        a.target = "_blank";
        a.rel = "noopener noreferrer";
        document.body.appendChild(a);
        a.click();
        a.remove();
      } catch { /* ignore */ }
    }

    const SEEN_KEY = "dsh-security-guard/seen-alerts";
    const SEEN_MSG_KEY = "dsh-security-guard/seen-alert-messages";
    const POPUP_MIN_INTERVAL = 10 * 60 * 1000; // 10 minutes
    let seenAlerts = [];
    let seenMessages = [];
    let lastPopupAt = 0;
    try { seenAlerts = JSON.parse(localStorage.getItem(SEEN_KEY) || "[]"); } catch { seenAlerts = []; }
    try { seenMessages = JSON.parse(localStorage.getItem(SEEN_MSG_KEY) || "[]"); } catch { seenMessages = []; }

    function alertSignature(event) {
      return `${event.level}::${event.message}`;
    }

    function markSeen(event) {
      if (!event || typeof event.id !== "string") return;
      if (!seenAlerts.includes(event.id)) seenAlerts.push(event.id);
      if (seenAlerts.length > 200) seenAlerts = seenAlerts.slice(-200);
      const sig = alertSignature(event);
      if (!seenMessages.includes(sig)) seenMessages.push(sig);
      if (seenMessages.length > 100) seenMessages = seenMessages.slice(-100);
      try {
        localStorage.setItem(SEEN_KEY, JSON.stringify(seenAlerts));
        localStorage.setItem(SEEN_MSG_KEY, JSON.stringify(seenMessages));
      } catch { /* ignore */ }
    }

    function closeModal(overlay) {
      if (overlay && overlay.parentNode) overlay.parentNode.removeChild(overlay);
    }

    function showRiskPopup(event) {
      if (typeof document === "undefined") return;
      const findings = Array.isArray(event?.details?.topFindings) ? event.details.topFindings : [];
      const overlay = document.createElement("div");
      overlay.className = "sg-modal-overlay";
      const modal = document.createElement("div");
      modal.className = "sg-modal";

      const head = document.createElement("div");
      head.className = "sg-modal-head";
      head.innerHTML = "🛡 大肥鱼安全卫士发现风险";
      modal.appendChild(head);

      const body = document.createElement("div");
      body.className = "sg-modal-body";
      const msg = document.createElement("div");
      msg.className = "sg-modal-msg";
      msg.textContent = event.message || "扫描发现高风险插件";
      body.appendChild(msg);

      if (findings.length > 0) {
        findings.slice(0, 5).forEach((f) => {
          const row = document.createElement("div");
          row.className = "sg-finding";
          const title = document.createElement("div");
          title.className = "sg-finding-title";
          const rid = document.createElement("span");
          rid.style.cssText = "color:#f85149;font-weight:700;";
          rid.textContent = f.ruleId || "";
          const rname = document.createElement("span");
          rname.textContent = f.ruleName || "";
          const where = document.createElement("span");
          where.style.cssText = "color:#8b949e;font-size:11px;";
          where.textContent = f.filePath ? f.filePath + ":" + (f.line || 0) : "";
          title.appendChild(rid);
          title.appendChild(rname);
          title.appendChild(where);
          row.appendChild(title);
          if (f.recommendation) {
            const rec = document.createElement("div");
            rec.className = "sg-finding-rec";
            rec.textContent = "建议：" + f.recommendation;
            row.appendChild(rec);
          }
          body.appendChild(row);
        });
      }
      modal.appendChild(body);

      const foot = document.createElement("div");
      foot.className = "sg-modal-foot";
      const handle = document.createElement("button");
      handle.className = "sg-btn sg-btn-primary";
      handle.textContent = "去处理";
      handle.onclick = () => { markSeen(event); closeModal(overlay); openDashboard(); };
      foot.appendChild(handle);
      const keep = document.createElement("button");
      keep.className = "sg-btn";
      keep.textContent = "保留，暂不处理";
      keep.onclick = () => { markSeen(event); closeModal(overlay); };
      foot.appendChild(keep);
      modal.appendChild(foot);

      overlay.appendChild(modal);
      document.body.appendChild(overlay);
    }

    async function pollAlerts() {
      try {
        const res = await fetch("/api/security-guard/getSecurityLog", {
          method: "POST",
          headers: { "content-type": "application/json" },
          credentials: "same-origin",
          body: "{}",
        });
        if (!res.ok) return;
        const logs = await res.json();
        if (!Array.isArray(logs)) return;
        const fresh = logs.filter((l) =>
          (l.level === "emergency" || l.level === "critical") &&
          !seenAlerts.includes(l.id) &&
          !seenMessages.includes(alertSignature(l))
        );
        if (fresh.length > 0 && Date.now() - lastPopupAt >= POPUP_MIN_INTERVAL) {
          const event = fresh[fresh.length - 1];
          lastPopupAt = Date.now();
          markSeen(event);
          showRiskPopup(event);
        }
      } catch { /* ignore */ }
    }

    function ShieldButton() {
      return react.createElement("button", {
        type: "button",
        title: "打开大肥鱼安全卫士仪表盘",
        "aria-label": "打开大肥鱼安全卫士仪表盘",
        className: "sg-shield",
        onClick: openDashboard,
      },
        react.createElement("span", { className: "sg-shield-icon" }, "🛡"),
        react.createElement("span", { className: "sg-shield-text" }, "安全卫士")
      );
    }

    const inject = ["slots"];

    function apply(ctx) {
      if (ctx && typeof ctx.slots?.inject === "function" && typeof ctx.slots.register === "function") {
        ctx.slots.inject("conversation.input.left", () =>
          ctx.slots.register(
            { name: "conversation.input.left", id: "security-guard-shield", order: 20, label: "安全卫士" },
            (props) => react.createElement(ShieldButton, props)
          )
        );
      }
      if (typeof window !== "undefined" && typeof document !== "undefined") {
        pollAlerts();
        setInterval(pollAlerts, 15000);
      }
    }

    exports.apply = apply;
    exports.inject = inject;
    return module.exports;
  }
});