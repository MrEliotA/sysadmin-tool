(() => {
  const $ = sel => document.querySelector(sel);
  const $$ = sel => Array.from(document.querySelectorAll(sel));
  const apiBase = "/api"; // توسط NGINX به سرویس بک‌اند پروکسی می‌شود

  const els = {
    form: $("#query-form"),
    input: $("#inputValue"),
    autoAnalyze: $("#autoAnalyze"),
    propCheck: $("#propCheck"),
    status: $("#statusBar"),

    dns: { body: $("#dnsBody"), badge: $("#dnsStatus") },
    ssl: { body: $("#sslBody"), badge: $("#sslStatus") },
    ip: { body: $("#ipBody"), badge: $("#ipStatus") },
    domain: { body: $("#domainBody"), badge: $("#domainStatus") },
    analyze: { body: $("#analyzeBody"), badge: $("#analyzeStatus") },
    prop: { body: $("#propBody"), badge: $("#propStatus") },

    resetBtn: $("#resetBtn"),
    copyAllBtn: $("#copyAllBtn"),
    spinnerTpl: $("#spinnerTpl")
  };

  let controllers = []; // برای لغو درخواست‌های قبلی

  function setBadge(badge, status, text) {
    badge.classList.remove("ok","warn","err");
    if (status === "ok") badge.classList.add("ok");
    if (status === "warn") badge.classList.add("warn");
    if (status === "err") badge.classList.add("err");
    badge.textContent = text;
  }

  function putSpinner(el) {
    el.classList.remove("empty");
    el.innerHTML = "";
    const node = els.spinnerTpl.content.cloneNode(true);
    el.appendChild(node);
  }

  function isIP(value){
    const v = value.trim();
    const ipv4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
    const ipv6 = /^([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}$/i;
    return ipv4.test(v) || ipv6.test(v);
  }

  function isDomain(value){
    const v = value.trim().toLowerCase();
    const re = /^(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,}$/;
    return re.test(v);
  }

  function fmt(value){
    if (value === null) return "null";
    if (value === undefined) return "undefined";
    if (typeof value === "string") return value;
    return JSON.stringify(value, null, 2);
  }

  function renderJSON(targetEl, data, titleKey=null){
    targetEl.classList.remove("empty");
    if (data == null) { targetEl.textContent = "—"; return; }

    if (Array.isArray(data) || typeof data !== "object"){
      targetEl.textContent = fmt(data);
      addCopyBtn(targetEl);
      return;
    }

    // برای آبجکت‌ها، نمای درختی + KV
    targetEl.innerHTML = "";
    const entries = Object.entries(data);
    for (const [k,v] of entries){
      if (v && typeof v === "object"){
        const det = document.createElement("details");
        det.className = "details";
        const sum = document.createElement("summary");
        sum.textContent = k;
        det.appendChild(sum);
        const pre = document.createElement("pre");
        pre.className = "monospace";
        pre.textContent = fmt(v);
        det.appendChild(pre);
        targetEl.appendChild(det);
      } else {
        const row = document.createElement("div");
        row.className = "kv";
        row.innerHTML = `<div class="key">${k}</div><div class="val">${fmt(v)}</div>`;
        targetEl.appendChild(row);
      }
    }
    addCopyBtn(targetEl);
  }

  function addCopyBtn(container){
    const btn = document.createElement("button");
    btn.className = "copy-btn";
    btn.textContent = "کپی این بخش";
    btn.addEventListener("click", () => copyElementText(container));
    container.appendChild(btn);
  }

  async function copyElementText(el){
    let text = el.innerText || el.textContent || "";
    try{
      await navigator.clipboard.writeText(text);
      toast("کپی شد.");
    }catch{
      toast("کپی ناموفق بود.", true);
    }
  }

  function toast(msg, isErr=false){
    els.status.textContent = msg;
    els.status.style.color = isErr ? "var(--err)" : "var(--subtle)";
    setTimeout(() => {
      els.status.textContent = "آماده.";
      els.status.style.color = "var(--subtle)";
    }, 3000);
  }

  function abortAll(){
    controllers.forEach(c => c.abort());
    controllers = [];
  }

  async function getJSON(url){
    const controller = new AbortController();
    controllers.push(controller);
    const res = await fetch(url, { signal: controller.signal });
    if (!res.ok){
      const text = await res.text().catch(()=>"");
      throw new Error(`HTTP ${res.status}: ${text || res.statusText}`);
    }
    // ممکنه برخی Endpointها جواب text بدهند؛ تلاش برای JSON سپس fallback
    const text = await res.text();
    try { return JSON.parse(text); }
    catch { return { raw: text }; }
  }

  function makeURL(endpoint, params){
    const usp = new URLSearchParams(params);
    return `${apiBase}${endpoint}${endpoint.includes("?") ? "&" : "?"}${usp.toString()}`;
  }

  async function runAll(rawInput){
    abortAll();
    const value = rawInput.trim();
    if (!value){ toast("ورودی خالی است.", true); return; }

    const type = isIP(value) ? "ip" : (isDomain(value) ? "domain" : null);
    if (!type){
      toast("لطفاً دامنه معتبر یا IP وارد کنید.", true);
      return;
    }

    // آماده‌سازی UI
    const blocks = [els.dns, els.ssl, els.ip, els.domain, els.analyze, els.prop];
    blocks.forEach(b=>{
      setBadge(b.badge, "", "در حال انتظار");
      b.body.classList.add("empty");
      b.body.textContent = "هنوز داده‌ای نیست.";
    });

    // تعیین اینکه کدام کارت‌ها باید اجرا شوند
    const runDNS = (type === "domain");
    const runSSL = (type === "domain");
    const runIP  = (type === "ip" || type === "domain"); // اگر دامنه بود، IP ممکن است از تحلیل دربیاید؛ اینجا endpoint مستقل IP فقط با IP کار می‌کند
    const runDomain = (type === "domain");
    const runAnalyze = $("#autoAnalyze").checked;
    const runProp = $("#propCheck").checked && (type === "domain");

    // برای مواردی که اجرا می‌شوند، اسپینر بگذار
    if (runDNS) putSpinner(els.dns.body);
    if (runSSL) putSpinner(els.ssl.body);
    if (type === "ip") putSpinner(els.ip.body);
    if (runDomain) putSpinner(els.domain.body);
    if (runAnalyze) putSpinner(els.analyze.body);
    if (runProp) putSpinner(els.prop.body);

    // درخواست‌ها
    const tasks = [];

    if (runDNS){
      tasks.push(
        getJSON(makeURL("/dns/", { domain: value }))
          .then(data => { renderJSON(els.dns.body, data); setBadge(els.dns.badge,"ok","موفق"); })
          .catch(err => { els.dns.body.textContent = err.message; setBadge(els.dns.badge,"err","خطا"); })
      );
    }

    if (runSSL){
      tasks.push(
        getJSON(makeURL("/ssl/ssl", { domain: value }))
          .then(data => { renderJSON(els.ssl.body, data); setBadge(els.ssl.badge,"ok","موفق"); })
          .catch(err => { els.ssl.body.textContent = err.message; setBadge(els.ssl.badge,"err","خطا"); })
      );
    }

    if (type === "ip"){
      tasks.push(
        getJSON(makeURL("/ip/", { target: value }))
          .then(data => { renderJSON(els.ip.body, data); setBadge(els.ip.badge,"ok","موفق"); })
          .catch(err => { els.ip.body.textContent = err.message; setBadge(els.ip.badge,"err","خطا"); })
      );
    }

    if (runDomain){
      tasks.push(
        getJSON(makeURL("/domain/", { domain: value }))
          .then(data => { renderJSON(els.domain.body, data); setBadge(els.domain.badge,"ok","موفق"); })
          .catch(err => { els.domain.body.textContent = err.message; setBadge(els.domain.badge,"err","خطا"); })
      );
    }

    if (runAnalyze){
      tasks.push(
        getJSON(makeURL("/analyze/analyze", { target: value }))
          .then(data => {
            renderJSON(els.analyze.body, data);
            setBadge(els.analyze.badge,"ok","موفق");
            // اگر در Analyze آدرس IP استخراج شد، کارت IP را هم پر کنیم (کمکی)
            try{
              const ipFromAnalyze = (data.ip || data.IP || (data.meta && data.meta.ip));
              if (ipFromAnalyze && !isIP(els.ip.body.textContent)){
                // فقط اگر هنوز کارت IP پر نشده
                els.ip.body.classList.remove("empty");
                renderJSON(els.ip.body, { fromAnalyze: ipFromAnalyze });
                setBadge(els.ip.badge,"warn","اطلاعات جانبی");
              }
            }catch{}
          })
          .catch(err => { els.analyze.body.textContent = err.message; setBadge(els.analyze.badge,"err","خطا"); })
      );
    }

    if (runProp){
      tasks.push(
        getJSON(makeURL("/dns/propagation", { domain: value }))
          .then(data => { renderJSON(els.prop.body, data); setBadge(els.prop.badge,"ok","موفق"); })
          .catch(err => { els.prop.body.textContent = err.message; setBadge(els.prop.badge,"err","خطا"); })
      );
    }

    Promise.allSettled(tasks).then(results=>{
      const errs = results.filter(r=>r.status==="rejected").length;
      if (errs>0) toast(`${errs} مورد با خطا مواجه شد.`, true);
      else toast("همه درخواست‌ها با موفقیت انجام شد ✅");
    });
  }

  // فرم
  els.form.addEventListener("submit", (e)=>{
    e.preventDefault();
    runAll(els.input.value);
  });

  // ریست
  els.resetBtn.addEventListener("click", ()=>{
    els.input.value = "";
    [els.dns,els.ssl,els.ip,els.domain,els.analyze,els.prop].forEach(b=>{
      setBadge(b.badge,"","در انتظار");
      b.body.classList.add("empty");
      b.body.textContent = "هنوز داده‌ای نیست.";
    });
    toast("ریست شد.");
  });

  // کپی همه
  els.copyAllBtn.addEventListener("click", ()=>{
    const text = $$(".card-body").map(x=>x.innerText).join("\n\n----------------\n\n");
    navigator.clipboard.writeText(text).then(()=>toast("همه نتایج کپی شد."), ()=>toast("کپی ناموفق بود.", true));
  });

  // Enter اولیه روی نمونه‌ها
  const qs = new URLSearchParams(location.search);
  if (qs.get("q")){
    els.input.value = qs.get("q");
    runAll(els.input.value);
  }
})();
