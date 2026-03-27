/**
 * Gerencia a interface do popup e exibe os dados coletados
 */

document.addEventListener("DOMContentLoaded", () => {
  // ==========================================
  // Inicialização
  // ==========================================
  initSectionToggles();
  initBlockingToggle();
  initButtons();
  loadData();

  // ==========================================
  // Carregar dados da aba ativa
  // ==========================================
  function loadData() {
    browser.tabs.query({ active: true, currentWindow: true }).then((tabs) => {
      if (!tabs[0]) return;
      const tab = tabs[0];

      // Mostrar URL do site
      document.getElementById("currentSite").textContent = new URL(tab.url).hostname || tab.url;

      // Pedir dados ao background script
      browser.runtime.sendMessage({ type: "getTabData", tabId: tab.id }).then((response) => {
        if (response && response.success) {
          renderData(response.data);
        } else {
          document.getElementById("scoreDescription").textContent = 
            "Navegue para uma página web para começar a análise.";
        }
      }).catch(() => {
        document.getElementById("scoreDescription").textContent = 
          "Navegue para uma página web para começar a análise.";
      });
    });
  }

  // ==========================================
  // Renderizar todos os dados
  // ==========================================
  function renderData(data) {
    // Pontuação de Privacidade
    renderScore(data.privacyScore);

    // Stats grid
    document.getElementById("thirdPartyCount").textContent = data.thirdPartyDomains.length;
    document.getElementById("trackerCount").textContent = data.trackerDomains.length;
    document.getElementById("blockedCount").textContent = data.blockedDomains.length;
    document.getElementById("cookieCount").textContent = data.cookies.total;

    // Rastreadores
    renderTrackers(data);

    // Cookies
    renderCookies(data.cookies, data.cookieSync);

    // localStorage
    renderStorage(data.localStorage);

    // Canvas Fingerprinting
    renderCanvas(data.canvasFingerprint);

    // Hijacking
    renderHijacking(data.hijacking);

    // Bloqueados
    renderBlocked(data.blockedDomains);
  }

  // ==========================================
  // Pontuação de Privacidade
  // ==========================================
  function renderScore(score) {
    const scoreNumber = document.getElementById("scoreNumber");
    const scoreFill = document.getElementById("scoreFill");
    const scoreDesc = document.getElementById("scoreDescription");

    scoreNumber.textContent = score;

    // Calcular dash offset (circunferência = 2 * π * 54 ≈ 339.292)
    const circumference = 339.292;
    const offset = circumference - (score / 100) * circumference;
    scoreFill.style.strokeDashoffset = offset;

    // Cor baseada na pontuação
    let color, description;
    if (score >= 80) {
      color = "#27ae60";
      description = "✅ Esta página respeita bem sua privacidade. Poucos rastreadores detectados.";
    } else if (score >= 60) {
      color = "#f39c12";
      description = "⚠️ Privacidade moderada. Alguns rastreadores e cookies de terceiros presentes.";
    } else if (score >= 40) {
      color = "#e67e22";
      description = "🔶 Privacidade baixa. Múltiplos rastreadores e técnicas de tracking detectados.";
    } else {
      color = "#e74c3c";
      description = "🔴 Privacidade crítica! Muitos rastreadores, fingerprinting e/ou ameaças detectadas.";
    }

    scoreFill.style.stroke = color;
    scoreNumber.style.color = color;
    scoreDesc.textContent = description;
  }

  // ==========================================
  // Rastreadores
  // ==========================================
  function renderTrackers(data) {
    const firstPartyList = document.getElementById("firstPartyTrackersList");
    const thirdPartyList = document.getElementById("thirdPartyTrackersList");

    // Rastreadores de 1ª parte
    if (data.firstPartyTrackers.length > 0) {
      firstPartyList.innerHTML = "";
      data.firstPartyTrackers.forEach((domain) => {
        firstPartyList.appendChild(createDomainItem(domain));
      });
    }

    // Rastreadores de 3ª parte
    if (data.thirdPartyTrackers.length > 0) {
      thirdPartyList.innerHTML = "";
      data.thirdPartyTrackers.forEach((domain) => {
        thirdPartyList.appendChild(createDomainItem(domain));
      });
    }
  }

  function createDomainItem(domain) {
    const item = document.createElement("div");
    item.className = "domain-item";

    const name = document.createElement("span");
    name.className = "domain-name";
    name.textContent = domain;

    const category = document.createElement("span");
    const cat = getTrackerCategoryName(domain);
    category.className = `domain-category cat-${cat.class}`;
    category.textContent = cat.label;

    item.appendChild(name);
    item.appendChild(category);
    return item;
  }

  function getTrackerCategoryName(domain) {
    // Categorias simplificadas para o popup
    const categories = {
      advertising: { label: "Anúncio", class: "advertising" },
      analytics: { label: "Analytics", class: "analytics" },
      social: { label: "Social", class: "social" },
      fingerprinting: { label: "Fingerprint", class: "fingerprinting" },
      cdn_tracking: { label: "CDN", class: "cdn_tracking" },
      unknown: { label: "Outro", class: "unknown" }
    };

    // Tentar identificar pela URL
    if (/ad|double|syndication|adsrvr|criteo|taboola|outbrain/i.test(domain)) {
      return categories.advertising;
    }
    if (/analytics|mixpanel|hotjar|segment|heap|chart/i.test(domain)) {
      return categories.analytics;
    }
    if (/facebook|twitter|linkedin|pinterest|tiktok|instagram/i.test(domain)) {
      return categories.social;
    }
    if (/fingerprint|iovation|threatmetrix/i.test(domain)) {
      return categories.fingerprinting;
    }
    return categories.unknown;
  }

  // ==========================================
  // Cookies
  // ==========================================
  function renderCookies(cookies, cookieSync) {
    document.getElementById("fp-session").textContent = cookies.firstParty.session;
    document.getElementById("fp-persistent").textContent = cookies.firstParty.persistent;
    document.getElementById("tp-session").textContent = cookies.thirdParty.session;
    document.getElementById("tp-persistent").textContent = cookies.thirdParty.persistent;
    document.getElementById("supercookies").textContent = cookies.superCookies;

    // Cookie Syncing
    if (cookieSync && cookieSync.detected) {
      const syncSection = document.getElementById("cookieSyncSection");
      syncSection.style.display = "block";
      const syncList = document.getElementById("cookieSyncList");
      syncList.innerHTML = "";

      cookieSync.chains.forEach((chain) => {
        const item = document.createElement("div");
        item.className = "domain-item";
        item.innerHTML = `
          <span class="domain-name">${chain.from} → ${chain.to}</span>
          <span class="domain-category cat-advertising">Sync</span>
        `;
        syncList.appendChild(item);
      });
    }
  }

  // ==========================================
  // localStorage
  // ==========================================
  function renderStorage(storage) {
    const status = document.getElementById("storageStatus");
    const details = document.getElementById("storageDetails");

    if (storage.detected) {
      status.className = "status-badge status-warning";
      status.textContent = "⚠️ Armazenamento detectado";
      details.style.display = "block";

      document.getElementById("storageKeyCount").textContent = storage.keys.length;
      document.getElementById("storageSize").textContent = formatSize(storage.size);

      const keysList = document.getElementById("storageKeysList");
      keysList.innerHTML = "";

      storage.keys.slice(0, 20).forEach((item) => {
        const keyItem = document.createElement("div");
        keyItem.className = "storage-key-item";
        keyItem.innerHTML = `
          <span class="key-name">${escapeHtml(item.key)}</span>
          <span class="key-preview">${escapeHtml(item.valuePreview)}</span>
        `;
        keysList.appendChild(keyItem);
      });

      if (storage.keys.length > 20) {
        const more = document.createElement("div");
        more.className = "empty";
        more.textContent = `+ ${storage.keys.length - 20} chaves adicionais...`;
        keysList.appendChild(more);
      }
    }
  }

  // ==========================================
  // Canvas Fingerprinting
  // ==========================================
  function renderCanvas(canvas) {
    const status = document.getElementById("canvasStatus");
    const details = document.getElementById("canvasDetails");

    if (canvas.detected) {
      status.className = "status-badge status-danger";
      status.textContent = "🔴 Fingerprinting detectado!";
      details.style.display = "block";
      document.getElementById("canvasAttempts").textContent = canvas.attempts;
    }
  }

  // ==========================================
  // Hijacking
  // ==========================================
  function renderHijacking(hijacking) {
    const status = document.getElementById("hijackingStatus");
    const list = document.getElementById("hijackingList");

    if (hijacking.detected && hijacking.threats.length > 0) {
      status.className = "status-badge status-danger";
      status.textContent = `🔴 ${hijacking.threats.length} ameaça(s) detectada(s)`;
      list.style.display = "block";
      list.innerHTML = "";

      hijacking.threats.forEach((threat) => {
        const item = document.createElement("div");
        item.className = "threat-item";
        item.innerHTML = `
          <span class="threat-type">${getThreatLabel(threat.type)}</span>
          <span class="threat-desc">${escapeHtml(threat.description)}</span>
        `;
        list.appendChild(item);
      });
    }
  }

  function getThreatLabel(type) {
    const labels = {
      suspicious_redirect: "🔄 Redirecionamento Suspeito",
      suspicious_script: "⚠️ Script Suspeito",
      direct_ip_request: "🌐 Requisição Direta a IP",
      hidden_iframe: "👁️ iFrame Oculto",
      suspicious_inline_script: "📝 Script Inline Suspeito",
      beef_framework: "🚨 Framework BeEF Detectado!"
    };
    return labels[type] || type;
  }

  // ==========================================
  // Bloqueados
  // ==========================================
  function renderBlocked(blockedDomains) {
    const list = document.getElementById("blockedList");
    if (blockedDomains.length > 0) {
      list.innerHTML = "";
      blockedDomains.forEach((domain) => {
        list.appendChild(createDomainItem(domain));
      });
    }
  }

  // ==========================================
  // Seções Expandíveis
  // ==========================================
  function initSectionToggles() {
    document.querySelectorAll(".section-header").forEach((header) => {
      header.addEventListener("click", () => {
        const targetId = header.getAttribute("data-target");
        const content = document.getElementById(targetId);
        const isActive = header.classList.contains("active");

        // Fechar todas as seções
        document.querySelectorAll(".section-header").forEach(h => h.classList.remove("active"));
        document.querySelectorAll(".section-content").forEach(c => c.classList.remove("show"));

        // Toggle da seção clicada
        if (!isActive) {
          header.classList.add("active");
          content.classList.add("show");
        }
      });
    });
  }

  // ==========================================
  // Toggle de Bloqueio
  // ==========================================
  function initBlockingToggle() {
    const toggle = document.getElementById("blockingToggle");
    const label = document.getElementById("toggleLabel");

    // Carregar estado
    browser.runtime.sendMessage({ type: "getSettings" }).then((response) => {
      if (response && response.success) {
        toggle.checked = response.settings.blockingEnabled;
        label.textContent = toggle.checked ? "Bloqueio Ativo" : "Bloqueio Inativo";
      }
    });

    toggle.addEventListener("change", () => {
      browser.runtime.sendMessage({ 
        type: "toggleBlocking", 
        enabled: toggle.checked 
      });
      label.textContent = toggle.checked ? "Bloqueio Ativo" : "Bloqueio Inativo";
    });
  }

  // ==========================================
  // Botões
  // ==========================================
  function initButtons() {
    document.getElementById("btnOptions").addEventListener("click", () => {
      browser.runtime.openOptionsPage();
    });

    document.getElementById("btnReport").addEventListener("click", () => {
      // Abrir todas as seções para formar o relatório visual
      document.querySelectorAll(".section-header").forEach(h => h.classList.add("active"));
      document.querySelectorAll(".section-content").forEach(c => c.classList.add("show"));
    });
  }

  // ==========================================
  // Utilitários
  // ==========================================
  function formatSize(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / (1024 * 1024)).toFixed(1) + " MB";
  }

  function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
  }
});
