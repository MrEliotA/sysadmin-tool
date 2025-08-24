(() => {
  const $ = sel => document.querySelector(sel);
  const $$ = sel => Array.from(document.querySelectorAll(sel));
  const apiBase = "/api";

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

  let controllers = [];

  /* -------------------- utils -------------------- */
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
    const v = String(value || "").trim();
    const ipv4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
    const ipv6 = /^([0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}$/i;
    return ipv4.test(v) || ipv6.test(v);
  }
  function isDomain(value){
    const v = String(value || "").trim().toLowerCase();
    const re = /^(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,}$/;
    return re.test(v);
  }
  function fmt(value){
    if (value === null) return "null";
    if (value === undefined) return "undefined";
    if (typeof value === "string") return value;
    return JSON.stringify(value, null, 2);
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
    const text = await res.text();
    try { return JSON.parse(text); }
    catch { return { raw: text }; }
  }
  function makeURL(endpoint, params){
    const usp = new URLSearchParams(params);
    return `${apiBase}${endpoint}${endpoint.includes("?") ? "&" : "?"}${usp.toString()}`;
  }

  /* -------------------- DNS: Cloudflare & Google, one line per record -------------------- */
  const TYPE_KEYS = ["SOA","NS","A","AAAA","CNAME","MX","TXT","CAA","SRV","PTR"];
  function recordValueToString(type, value){
    try{
      if (value == null) return "";
      if (typeof value === "string" || typeof value === "number") return String(value);

      if (type === "MX"){
        const pref = value.preference ?? value.priority ?? value.pref;
        const exch = value.exchange ?? value.target ?? value.host ?? value.value ?? value.data;
        if (pref != null && exch) return `${pref} ${exch}`;
        if (exch) return String(exch);
      }
      if (type === "SRV"){
        const pr = value.priority ?? value.pr;
        const w  = value.weight ?? value.w;
        const pt = value.port ?? value.service_port;
        const tg = value.target ?? value.name ?? value.host;
        const parts = [pr,w,pt,tg].filter(x=>x!=null).map(String);
        if (parts.length) return parts.join(" ");
      }
      if (type === "SOA"){
        const mname = value.mname ?? value.primary ?? value.nsname;
        const rname = value.rname ?? value.mail ?? value.hostmaster;
        const serial = value.serial ?? value.sn;
        const refresh = value.refresh ?? value.ref;
        const retry = value.retry;
        const expire = value.expire ?? value.ex;
        const minimum = value.minimum ?? value.min;
        const parts = [mname,rname,serial,refresh,retry,expire,minimum].filter(Boolean);
        if (parts.length) return parts.join(" ");
      }
      if (type === "CAA"){
        const flags = value.flags ?? value.flag;
        const tag = value.tag;
        const val = value.value ?? value.val ?? value.data;
        const parts = [flags,tag,val].filter(x=>x!=null).map(String);
        if (parts.length) return parts.join(" ");
      }
      if (type === "TXT"){
        const txt = value.txt ?? value.value ?? value.data;
        if (Array.isArray(txt)) return txt.join(" ");
        if (txt != null) return String(txt);
      }
      const val = value.value ?? value.data ?? value.target ?? value.exchange ?? value.addr ?? value.ip ?? value.host ?? value.name;
      if (val != null) return Array.isArray(val) ? val.join(", ") : String(val);
      return JSON.stringify(value);
    }catch{
      return String(value);
    }
  }
  function renderDNSProviderBlock(title, providerObj){
    const wrap = document.createElement("div");
    wrap.style.marginBottom = "10px";

    const head = document.createElement("div");
    head.textContent = title;
    head.style.fontWeight = "700";
    head.style.marginBottom = "6px";
    head.style.textAlign = "left";
    head.style.direction = "ltr";
    wrap.appendChild(head);

    const pre = document.createElement("pre");
    pre.className = "monospace";
    pre.style.whiteSpace = "pre";
    pre.style.textAlign = "left";
    pre.style.direction = "ltr";
    pre.style.overflow = "auto";

    const lines = [];
    if (providerObj && typeof providerObj === "object"){
      TYPE_KEYS.forEach(t=>{
        const v = providerObj[t];
        if (v == null) return;
        if (Array.isArray(v)){
          v.forEach(item => lines.push(`${t}: ${recordValueToString(t, item)}`));
        } else {
          lines.push(`${t}: ${recordValueToString(t, v)}`);
        }
      });
    }
    pre.textContent = lines.length ? lines.join("\n") : "(رکوردی یافت نشد)";
    wrap.appendChild(pre);
    return wrap;
  }
  function renderDNS_CF_Google(targetEl, data){
    targetEl.classList.remove("empty");
    targetEl.innerHTML = "";
    const servers = (data && data.servers) || {};

    const cf = servers.Cloudflare || servers.cloudflare || servers["1.1.1.1"];
    targetEl.appendChild(renderDNSProviderBlock("Cloudflare", cf));

    const gg = servers.Google || servers.google || servers["8.8.8.8"] || servers["dns.google"];
    targetEl.appendChild(renderDNSProviderBlock("Google", gg));

    addCopyBtn(targetEl);
  }

  /* -------------------- shared path helpers -------------------- */
  function getPathCI(obj, pathArr){
    let cur = obj;
    for (const seg of pathArr){
      if (cur == null || typeof cur !== "object") return undefined;
      const keyLC = String(seg).toLowerCase();
      const foundKey = Object.keys(cur).find(k => k.toLowerCase() === keyLC);
      if (!foundKey) return undefined;
      cur = cur[foundKey];
    }
    return cur;
  }
  function getByPaths(obj, paths){
    for (const p of paths){
      const v = getPathCI(obj, p);
      if (v !== undefined) return v;
    }
    return undefined;
  }
  const toLineValue = v =>
    v == null ? "—" : (Array.isArray(v) ? v.join(", ") : (typeof v === "object" ? JSON.stringify(v) : String(v)));

  /* -------------------- SSL (left aligned) -------------------- */
  function parseDateMaybe(s){
    if (!s) return null;
    const dt = new Date(s);
    if (!isNaN(dt)) return dt;
    const t = Date.parse(String(s));
    if (!isNaN(t)) return new Date(t);
    return null;
  }
  function daysDiffFromNow(targetDate){
    const dt = parseDateMaybe(targetDate);
    if (!dt) return null;
    const ms = dt.getTime() - Date.now();
    return Math.ceil(ms / (1000*60*60*24));
  }
  function renderSSLCard(targetEl, data){
    targetEl.classList.remove("empty");
    targetEl.innerHTML = "";

    let days = getByPaths(data, [
      ["local_certificate","days_remaining"],
      ["days_remaining"]
    ]);
    let daysNum = Number(days);
    if (!Number.isFinite(daysNum)) {
      const notAfter = getByPaths(data, [
        ["local_certificate","not_valid_after"],
        ["not_valid_after"]
      ]);
      const computed = daysDiffFromNow(notAfter);
      daysNum = Number.isFinite(computed) ? computed : NaN;
    }

    const metricRow = document.createElement("div");
    metricRow.style.display = "flex";
    metricRow.style.alignItems = "center";
    metricRow.style.justifyContent = "flex-start";
    metricRow.style.gap = "10px";
    metricRow.style.textAlign = "left";
    const metricNum = document.createElement("div");
    metricNum.className = "metric " + (Number.isFinite(daysNum) ? (daysNum < 10 ? "bad" : "ok") : "muted");
    metricNum.style.textAlign = "left";
    metricNum.textContent = Number.isFinite(daysNum) ? String(daysNum) : "—";
    const metricLbl = document.createElement("div");
    metricLbl.textContent = "days left";
    metricLbl.style.fontSize = "14px";
    metricLbl.style.color = "var(--subtle)";
    metricLbl.style.textAlign = "left";
    metricRow.appendChild(metricNum);
    metricRow.appendChild(metricLbl);
    targetEl.appendChild(metricRow);

    const gradeCaption = document.createElement("div");
    gradeCaption.textContent = "Grade";
    gradeCaption.style.textAlign = "left";
    gradeCaption.style.fontSize = "12px";
    gradeCaption.style.color = "var(--subtle)";
    gradeCaption.style.marginTop = "-4px";
    targetEl.appendChild(gradeCaption);

    const gradesVal = getByPaths(data, [
      ["ssl_labs_summary","grades"],
      ["ssl_labs_summary","overall_grade"],
      ["grades"], ["overall_grade"]
    ]);
    if (gradesVal !== undefined){
      const g = document.createElement("div");
      g.className = "grade";
      g.style.textAlign = "left";
      g.textContent = toLineValue(gradesVal) || "—";
      targetEl.appendChild(g);
    }

    const lines = document.createElement("div");
    lines.className = "ssl-lines";
    lines.style.textAlign = "left";

    const subjCN = getByPaths(data, [["local_certificate","subject","commonName"], ["subject","commonName"]]);
    const issuerCN  = getByPaths(data, [["local_certificate","issuer","commonName"], ["issuer","commonName"]]);
    const issuerOrg = getByPaths(data, [["local_certificate","issuer","organizationName"], ["issuer","organizationName"]]);
    const issuerCountry = getByPaths(data, [["local_certificate","issuer","countryName"], ["issuer","countryName"]]);
    const nva = getByPaths(data, [["local_certificate","not_valid_after"], ["not_valid_after"]]);
    const nvb = getByPaths(data, [["local_certificate","not_valid_before"], ["not_valid_before"]]);
    const sig = getByPaths(data, [["local_certificate","signature_algorithm"], ["signature_algorithm"]]);
    const ver = getByPaths(data, [["local_certificate","version"], ["version"]]);
    const protocols = getByPaths(data, [["ssl_labs_summary","protocols"], ["protocols"]]);
    const vulns = getByPaths(data, [["ssl_labs_summary","vulnerabilities"], ["vulnerabilities"]]);

    const rows = [
      ["commonName", subjCN],
      ["countryName", issuerCountry],
      ["not_valid_after", nva],
      ["not_valid_before", nvb],
      ["signature_algorithm", sig],
      ["commonName", issuerCN],
      ["organizationName", issuerOrg],
      ["version", ver],
      ["grades", gradesVal],
      ["protocols", protocols],
      ["vulnerabilities", vulns],
    ];

    rows.forEach(([label, val])=>{
      const line = document.createElement("div");
      line.className = "kv-line";
      const k = document.createElement("span");
      k.className = "key";
      k.textContent = `${label}: `;
      const v = document.createElement("span");
      v.className = "val";
      v.textContent = toLineValue(val);
      line.appendChild(k);
      line.appendChild(v);
      lines.appendChild(line);
    });

    targetEl.appendChild(lines);
    addCopyBtn(targetEl);
  }

  /* -------------------- IP Info: ordered, left-aligned -------------------- */
  function renderIPInfoOrdered(targetEl, data){
    targetEl.classList.remove("empty");
    targetEl.innerHTML = "";

    const box = document.createElement("div");
    box.className = "ssl-lines";
    box.style.textAlign = "left";
    box.style.direction = "ltr";

    const mapping = [
      ["as",          [ ["as"], ["raw","as"] ]],
      ["continent",   [ ["raw","continent"] ]],
      ["city",        [ ["city"], ["raw","city"] ]],
      ["country",     [ ["country"], ["raw","country"] ]],
      ["lat",         [ ["lat"], ["raw","lat"] ]],
      ["lon",         [ ["lon"], ["raw","lon"] ]],
      ["regionName",  [ ["raw","regionName"] ]],
      ["timezone",    [ ["timezone"], ["raw","timezone"] ]],
      ["zip",         [ ["zip"], ["raw","zip"] ]],
      ["hosting",     [ ["raw","hosting"] ]],
      ["reverse",     [ ["raw","reverse"], ["reverse_dns"] ]],
    ];

    mapping.forEach(([label, paths])=>{
      const val = getByPaths(data, paths);
      const line = document.createElement("div");
      line.className = "kv-line";
      line.style.textAlign = "left";
      const k = document.createElement("span");
      k.className = "key";
      k.textContent = `${label}: `;
      const v = document.createElement("span");
      v.className = "val";
      v.textContent = (val === null || val === undefined) ? "—" :
                      (typeof val === "object" ? JSON.stringify(val) : String(val));
      line.appendChild(k);
      line.appendChild(v);
      box.appendChild(line);
    });

    targetEl.appendChild(box);
    addCopyBtn(targetEl);
  }

  /* -------------------- Domain Info: unified, WITH keys (ordered) -------------------- */
  function renderDomainInfoUnifiedWithKeys(targetEl, data){
    targetEl.classList.remove("empty");
    targetEl.innerHTML = "";

    let rawObj = null;
    try { rawObj = data.raw ? JSON.parse(data.raw) : null; } catch { rawObj = null; }

    const box = document.createElement("div");
    box.className = "ssl-lines";
    box.style.textAlign = "left";
    box.style.direction = "ltr";

    const addKV = (key, val) => {
      const line = document.createElement("div");
      line.className = "kv-line";
      const k = document.createElement("span");
      k.className = "key";
      k.textContent = `${key}: `;
      const v = document.createElement("span");
      v.className = "val";
      v.textContent = (val === null || val === undefined || val === "") ? "—" : String(val);
      line.appendChild(k);
      line.appendChild(v);
      box.appendChild(line);
    };

    // ترتیب مورد نظر:
    addKV("creation_date", data.creation_date ?? (rawObj && rawObj.creation_date));
    addKV("expiration_date", data.expiration_date ?? (rawObj && rawObj.expiration_date));

    let updated = (rawObj && rawObj.updated_date) ?? data.updated_date;
    if (Array.isArray(updated)) updated = updated.join(", ");
    addKV("updated_date", updated);

    addKV("status", (rawObj && rawObj.status) ?? data.status);

    // name_servers: هر مورد در خط خودش با همان کلید
    const nsList = Array.isArray(data.name_servers) ? data.name_servers
                 : (data.name_servers ? [data.name_servers] : []);
    if (nsList.length) nsList.forEach(ns => addKV("name_servers", ns));
    else addKV("name_servers", "—");

    // سایر آیتم‌های مهم (با کلید)
    addKV("registrar", (rawObj && rawObj.registrar) ?? data.registrar);
    addKV("dnssec", rawObj ? rawObj.dnssec : undefined);
    addKV("name", rawObj ? rawObj.name : undefined);
    addKV("org", rawObj ? rawObj.org : undefined);
    addKV("address", rawObj ? rawObj.address : undefined);
    addKV("city", rawObj ? rawObj.city : undefined);
    addKV("state", rawObj ? rawObj.state : undefined);
    addKV("country", rawObj ? rawObj.country : undefined);
    addKV("emails", data.emails ?? (rawObj && rawObj.emails));
    addKV("whois_server", data.whois_server ?? (rawObj && rawObj.whois_server));

    targetEl.appendChild(box);
    addCopyBtn(targetEl);
  }

  /* -------------------- Analyze: robust fallback to avoid 502 -------------------- */
  async function fetchAnalyzeData(target){
    const candidates = [
      ["/analyze/analyze", { target }],
      ["/analyze/analyze/", { target }],
      ["/analyze/", { target }],
      ["/analyze", { target }],
    ];
    let lastErr = null;
    for (const [ep, params] of candidates){
      try{
        const data = await getJSON(makeURL(ep, params));
        return data;
      }catch(err){
        lastErr = err;
        // اگر 502/404 بود، مسیر بعدی را امتحان کن
        if (!/HTTP (502|404)/.test(err.message)) {
          // سایر خطاها را همانجا گزارش کن
          throw err;
        }
      }
    }
    throw lastErr || new Error("Analyze endpoint not reachable");
  }

  /* -------------------- helpers -------------------- */
  function pickIPFromDNS(data){
    const found = new Set();
    const pushIfIP = (s) => {
      if (!s) return;
      const str = String(s);
      const v4m = str.match(/\b(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g);
      if (v4m) v4m.forEach(ip => found.add(ip));
      const v6m = str.match(/\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b/g);
      if (v6m) v6m.forEach(ip => found.add(ip));
      if (isIP(str)) found.add(str);
    };
    const walk = (val) => {
      if (val == null) return;
      if (typeof val === "string" || typeof val === "number") { pushIfIP(val); return; }
      if (Array.isArray(val)) { val.forEach(walk); return; }
      if (typeof val === "object") {
        const keys = Object.keys(val);
        ["A","AAAA","ip","IP","address","addresses","resolved_ip","data","answer","value"].forEach(k=>{
          if (k in val) walk(val[k]);
        });
        keys.forEach(k => walk(val[k]));
      }
    };
    walk(data);
    const list = [...found].filter(isIP);
    const v4 = list.find(ip => /^\d+\.\d+\.\d+\.\d+$/.test(ip));
    return v4 || list[0] || null;
  }
  async function renderJSONSimple(targetEl, data){
    targetEl.classList.remove("empty");
    targetEl.innerHTML = "";
    const pre = document.createElement("pre");
    pre.className = "monospace";
    pre.style.whiteSpace = "pre-wrap";
    pre.style.wordBreak = "break-word";
    pre.style.overflowWrap = "anywhere";
    pre.style.textAlign = "left";
    pre.style.direction = "ltr";
    pre.textContent = fmt(data);
    targetEl.appendChild(pre);
    addCopyBtn(targetEl);
  }

  async function fetchAndFillIP(ip){
    if (!ip || !isIP(ip)) return;
    putSpinner(els.ip.body);
    setBadge(els.ip.badge, "", "در حال بررسی");
    try{
      const data = await getJSON(makeURL("/ip/", { target: ip }));
      renderIPInfoOrdered(els.ip.body, data);
      setBadge(els.ip.badge, "ok", "موفق");
    }catch(err){
      els.ip.body.textContent = err.message;
      setBadge(els.ip.badge, "err", "خطا");
    }
  }

  /* -------------------- runner -------------------- */
  async function runAll(rawInput){
    abortAll();
    const value = rawInput.trim();
    if (!value){ toast("ورودی خالی است.", true); return; }

    const type = isIP(value) ? "ip" : (isDomain(value) ? "domain" : null);
    if (!type){
      toast("لطفاً دامنه معتبر یا IP وارد کنید.", true);
      return;
    }

    const blocks = [els.dns, els.ssl, els.ip, els.domain, els.analyze, els.prop];
    blocks.forEach(b=>{
      setBadge(b.badge, "", "در انتظار");
      b.body.classList.add("empty");
      b.body.textContent = "هنوز داده‌ای نیست.";
    });

    const runDNS = (type === "domain");
    const runSSL = (type === "domain");
    const runDomain = (type === "domain");
    const runAnalyze = els.autoAnalyze.checked;
    const runProp = els.propCheck.checked && (type === "domain");

    if (type === "ip") {
      putSpinner(els.ip.body);
      setBadge(els.ip.badge, "", "در حال بررسی");
      getJSON(makeURL("/ip/", { target: value }))
        .then(data => { renderIPInfoOrdered(els.ip.body, data); })
        .then(()=> setBadge(els.ip.badge,"ok","موفق"))
        .catch(err => { els.ip.body.textContent = err.message; setBadge(els.ip.badge,"err","خطا"); });
    }

    if (runDNS) putSpinner(els.dns.body);
    if (runSSL) putSpinner(els.ssl.body);
    if (runDomain) putSpinner(els.domain.body);
    if (runAnalyze) putSpinner(els.analyze.body);
    if (runProp) putSpinner(els.prop.body);

    const tasks = [];

    // DNS
    if (runDNS){
      tasks.push(
        getJSON(makeURL("/dns/", { domain: value }))
          .then(async data => {
            renderDNS_CF_Google(els.dns.body, data);
            setBadge(els.dns.badge,"ok","موفق");

            const ipFromDNS = pickIPFromDNS(data);
            if (ipFromDNS) {
              await fetchAndFillIP(ipFromDNS);
            } else if (els.ip.body.classList.contains("empty")) {
              els.ip.body.textContent = "IP در پاسخ DNS پیدا نشد.";
              setBadge(els.ip.badge, "warn", "یافت نشد");
            }
          })
          .catch(err => { els.dns.body.textContent = err.message; setBadge(els.dns.badge,"err","خطا"); })
      );
    }

    // SSL
    if (runSSL){
      tasks.push(
        getJSON(makeURL("/ssl/ssl", { domain: value }))
          .then(data => {
            renderSSLCard(els.ssl.body, data);
            setBadge(els.ssl.badge,"ok","موفق");
          })
          .catch(err => { els.ssl.body.textContent = err.message; setBadge(els.ssl.badge,"err","خطا"); })
      );
    }

    // Domain (یکدست + با کلید)
    if (runDomain){
      tasks.push(
        getJSON(makeURL("/domain/", { domain: value }))
          .then(data => renderDomainInfoUnifiedWithKeys(els.domain.body, data))
          .then(()=> setBadge(els.domain.badge,"ok","موفق"))
          .catch(err => { els.domain.body.textContent = err.message; setBadge(els.domain.badge,"err","خطا"); })
      );
    }

    // Analyze (fallback مسیرها برای جلوگیری از 502)
    if (runAnalyze){
      tasks.push(
        fetchAnalyzeData(value)
          .then(data => {
            renderJSONSimple(els.analyze.body, data);
            setBadge(els.analyze.badge,"ok","موفق");
            try{
              const ipFromAnalyze =
                (data && (data.ip || data.IP || (data.meta && data.meta.ip))) || null;
              if (ipFromAnalyze && els.ip.body.classList.contains("empty")) {
                fetchAndFillIP(ipFromAnalyze);
              }
            }catch{}
          })
          .catch(err => {
            els.analyze.body.textContent = err.message;
            setBadge(els.analyze.badge,"err","خطا");
          })
      );
    }

    // Propagation
    if (runProp){
      tasks.push(
        getJSON(makeURL("/dns/propagation", { domain: value }))
          .then(data => renderJSONSimple(els.prop.body, data))
          .then(()=> setBadge(els.prop.badge,"ok","موفق"))
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

  // اجرای خودکار با ?q=
  const qs = new URLSearchParams(location.search);
  if (qs.get("q")){
    els.input.value = qs.get("q");
    runAll(els.input.value);
  }
})();
