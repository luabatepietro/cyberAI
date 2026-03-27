/**
 * 
 * Responsável por:
 * - Interceptar e analisar requisições HTTP
 * - Detectar conexões de terceiros
 * - Monitorar cookies (1ª e 3ª parte, sessão e persistente)
 * - Bloquear domínios de rastreamento
 * - Calcular pontuação de privacidade
 * - Detectar potenciais ameaças de hijacking
 */

// ==========================================
// Estado global por aba
// ==========================================
const tabData = {};

function initTabData(tabId, url) {
  const hostname = getHostname(url);
  tabData[tabId] = {
    url: url,
    hostname: hostname,
    thirdPartyDomains: new Set(),
    trackerDomains: new Set(),
    blockedDomains: new Set(),
    firstPartyTrackers: new Set(),
    thirdPartyTrackers: new Set(),
    cookies: {
      firstParty: { session: 0, persistent: 0 },
      thirdParty: { session: 0, persistent: 0 },
      total: 0,
      superCookies: 0
    },
    localStorage: {
      detected: false,
      keys: [],
      size: 0
    },
    canvasFingerprint: {
      detected: false,
      attempts: 0
    },
    hijacking: {
      detected: false,
      threats: []
    },
    cookieSync: {
      detected: false,
      chains: []
    },
    totalRequests: 0,
    blockedRequests: 0,
    privacyScore: 100,
    timestamp: Date.now()
  };
  console.log("[PrivacyShield] initTabData tab=" + tabId + " host=" + hostname + " url=" + url);
}

// ==========================================
// Utilitários
// ==========================================
function getHostname(url) {
  try {
    const u = new URL(url);
    // Para file:// URLs, retornar um identificador válido
    if (u.protocol === "file:") return "local-file";
    return u.hostname;
  } catch (e) {
    return "";
  }
}

function getDomain(hostname) {
  if (!hostname || hostname === "local-file") return hostname;
  const parts = hostname.split(".");
  if (parts.length <= 2) return hostname;
  return parts.slice(-2).join(".");
}

function isThirdParty(requestHost, pageHost) {
  if (!requestHost || !pageHost) return false;
  // file:// pages: qualquer requisição externa é de terceiro
  if (pageHost === "local-file") return requestHost !== "local-file";
  return getDomain(requestHost) !== getDomain(pageHost);
}

// ==========================================
// Configurações (carregadas do storage)
// ==========================================
let settings = {
  blockingEnabled: true,
  customBlocklist: [],
  customWhitelist: [],
  showNotifications: true
};

browser.storage.local.get("settings").then((result) => {
  if (result.settings) {
    settings = { ...settings, ...result.settings };
  }
});

browser.storage.onChanged.addListener((changes) => {
  if (changes.settings) {
    settings = { ...settings, ...changes.settings.newValue };
  }
});

// ==========================================
// Verificação de bloqueio
// ==========================================
function shouldBlock(hostname) {
  if (settings.customWhitelist.some(d => hostname === d || hostname.endsWith("." + d))) {
    return false;
  }
  if (settings.customBlocklist.some(d => hostname === d || hostname.endsWith("." + d))) {
    return true;
  }
  return isTrackerDomain(hostname);
}

// ==========================================
// Interceptação de requisições web
// ==========================================
browser.webRequest.onBeforeRequest.addListener(
  (details) => {
    const tabId = details.tabId;
    if (tabId < 0) return {};

    // MAIN FRAME: a própria página sendo carregada - inicializar tabData
    if (details.type === "main_frame") {
      initTabData(tabId, details.url);
      return {};
    }

    // SUB-REQUISIÇÃO: se tabData não existe, inicializar com a URL de origem
    if (!tabData[tabId]) {
      const pageUrl = details.documentUrl || details.originUrl || "";
      if (pageUrl) {
        initTabData(tabId, pageUrl);
      } else {
        return {};
      }
    }

    const requestHost = getHostname(details.url);
    const pageHost = tabData[tabId].hostname;
    if (!requestHost || !pageHost) return {};

    tabData[tabId].totalRequests++;

    // Detectar conexões de terceiros
    if (isThirdParty(requestHost, pageHost)) {
      tabData[tabId].thirdPartyDomains.add(requestHost);

      if (isTrackerDomain(requestHost)) {
        tabData[tabId].thirdPartyTrackers.add(requestHost);
        tabData[tabId].trackerDomains.add(requestHost);
      }
    } else {
      if (isTrackerDomain(requestHost)) {
        tabData[tabId].firstPartyTrackers.add(requestHost);
        tabData[tabId].trackerDomains.add(requestHost);
      }
    }

    detectCookieSync(details, tabId);
    detectHijacking(details, tabId);

    // Bloquear se necessário
    if (settings.blockingEnabled && isThirdParty(requestHost, pageHost) && shouldBlock(requestHost)) {
      tabData[tabId].blockedDomains.add(requestHost);
      tabData[tabId].blockedRequests++;
      updateBadge(tabId);
      return { cancel: true };
    }

    return {};
  },
  { urls: ["<all_urls>"] },
  ["blocking"]
);

// ==========================================
// Monitoramento de headers
// ==========================================
browser.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    const tabId = details.tabId;
    if (tabId < 0 || !tabData[tabId]) return {};

    const cookieHeader = details.requestHeaders.find(h => h.name.toLowerCase() === "cookie");
    if (cookieHeader && isThirdParty(getHostname(details.url), tabData[tabId].hostname)) {
      const requestHost = getHostname(details.url);
      if (isTrackerDomain(requestHost)) {
        const url = details.url;
        if (/[?&](uid|id|pid|sid|visitor|user)=/i.test(url)) {
          tabData[tabId].cookieSync.detected = true;
          tabData[tabId].cookieSync.chains.push({
            from: tabData[tabId].hostname,
            to: requestHost,
            url: url.substring(0, 100) + "..."
          });
        }
      }
    }
    return {};
  },
  { urls: ["<all_urls>"] },
  ["requestHeaders"]
);

browser.webRequest.onHeadersReceived.addListener(
  (details) => {
    const tabId = details.tabId;
    if (tabId < 0 || !tabData[tabId]) return {};

    const responseHost = getHostname(details.url);
    const pageHost = tabData[tabId].hostname;
    const isThird = isThirdParty(responseHost, pageHost);

    details.responseHeaders.forEach((header) => {
      if (header.name.toLowerCase() === "set-cookie") {
        tabData[tabId].cookies.total++;

        const isSession = !header.value.toLowerCase().includes("expires=") && 
                         !header.value.toLowerCase().includes("max-age=");
        const isSuperCookie = checkSuperCookie(header.value);
        if (isSuperCookie) {
          tabData[tabId].cookies.superCookies++;
        }

        if (isThird) {
          if (isSession) tabData[tabId].cookies.thirdParty.session++;
          else tabData[tabId].cookies.thirdParty.persistent++;
        } else {
          if (isSession) tabData[tabId].cookies.firstParty.session++;
          else tabData[tabId].cookies.firstParty.persistent++;
        }
      }

      if (header.name.toLowerCase() === "refresh" || 
          (header.name.toLowerCase() === "location" && details.statusCode >= 300 && details.statusCode < 400)) {
        const redirectUrl = header.value;
        const redirectHost = getHostname(redirectUrl);
        if (redirectHost && isThirdParty(redirectHost, pageHost) && isTrackerDomain(redirectHost)) {
          tabData[tabId].hijacking.detected = true;
          tabData[tabId].hijacking.threats.push({
            type: "suspicious_redirect",
            from: responseHost,
            to: redirectHost,
            description: "Redirecionamento suspeito para domínio de rastreamento"
          });
        }
      }
    });
    return {};
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

// ==========================================
// Detecção de Supercookies
// ==========================================
function checkSuperCookie(cookieValue) {
  const lower = cookieValue.toLowerCase();
  const maxAgeMatch = lower.match(/max-age=(\d+)/);
  if (maxAgeMatch) {
    const seconds = parseInt(maxAgeMatch[1]);
    if (seconds > 365 * 24 * 60 * 60) return true;
  }
  const expiresMatch = lower.match(/expires=([^;]+)/);
  if (expiresMatch) {
    try {
      const expireDate = new Date(expiresMatch[1]);
      const now = new Date();
      const diffYears = (expireDate - now) / (1000 * 60 * 60 * 24 * 365);
      if (diffYears > 1) return true;
    } catch (e) {}
  }
  if (/[a-f0-9]{32,}/i.test(cookieValue.split("=")[1] || "")) {
    return true;
  }
  return false;
}

// ==========================================
// Detecção de Cookie Syncing
// ==========================================
function detectCookieSync(details, tabId) {
  const url = details.url;
  const syncPatterns = [
    /\/sync\?/i, /\/cookie-sync/i, /\/match\?/i,
    /\/cm\?/i, /\/usersync/i, /\/pixel.*[?&].*id=/i, /bounce.*redirect/i
  ];
  if (syncPatterns.some(pattern => pattern.test(url))) {
    tabData[tabId].cookieSync.detected = true;
    tabData[tabId].cookieSync.chains.push({
      from: tabData[tabId].hostname,
      to: getHostname(url),
      pattern: "URL sync pattern detected"
    });
  }
}

// ==========================================
// Detecção de Hijacking
// ==========================================
function detectHijacking(details, tabId) {
  const suspiciousPatterns = [
    /hook\.js/i, /beef.*hook/i, /exploit.*framework/i, /keylog/i, /xss.*payload/i
  ];
  if (suspiciousPatterns.some(p => p.test(details.url))) {
    tabData[tabId].hijacking.detected = true;
    tabData[tabId].hijacking.threats.push({
      type: "suspicious_script",
      url: details.url,
      description: "Script suspeito detectado (possível framework de exploração)"
    });
  }

  const hostname = getHostname(details.url);
  if (/^(\d+\.){3}\d+$/.test(hostname)) {
    if (isThirdParty(hostname, tabData[tabId].hostname)) {
      tabData[tabId].hijacking.threats.push({
        type: "direct_ip_request",
        url: details.url,
        description: "Requisição direta para endereço IP (possível C&C)"
      });
    }
  }
}

// ==========================================
// Eventos de navegação
// ==========================================
browser.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // Inicializar quando a aba começa a carregar
  if (changeInfo.status === "loading" && tab.url) {
    initTabData(tabId, tab.url);
    updateBadge(tabId);
  }
});

try {
  browser.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId === 0) {
      initTabData(details.tabId, details.url);
    }
  });
  console.log("[PrivacyShield] webNavigation listener registered");
} catch (e) {
  console.warn("[PrivacyShield] webNavigation not available:", e);
}

// CRÍTICO: Inicializar dados para todas as abas já abertas quando a extensão carrega
browser.tabs.query({}).then((tabs) => {
  for (const tab of tabs) {
    if (tab.url && tab.id >= 0) {
      initTabData(tab.id, tab.url);
    }
  }
  console.log("[PrivacyShield] Pre-initialized " + tabs.length + " tabs on startup");
}).catch((e) => {
  console.warn("[PrivacyShield] tabs.query failed:", e);
});

browser.tabs.onRemoved.addListener((tabId) => {
  delete tabData[tabId];
});

// ==========================================
// Badge do ícone
// ==========================================
function updateBadge(tabId) {
  if (!tabData[tabId]) return;
  const blocked = tabData[tabId].blockedDomains.size;
  const trackers = tabData[tabId].trackerDomains.size;
  const count = blocked > 0 ? blocked : trackers;
  const text = count > 0 ? String(count) : "";
  const color = blocked > 0 ? "#e74c3c" : (trackers > 0 ? "#f39c12" : "#27ae60");
  
  browser.browserAction.setBadgeText({ text, tabId });
  browser.browserAction.setBadgeBackgroundColor({ color, tabId });
}

// ==========================================
// Cálculo da Pontuação de Privacidade
// ==========================================
function calculatePrivacyScore(tabId) {
  if (!tabData[tabId]) return 100;

  let score = 100;
  const data = tabData[tabId];

  score -= Math.min(30, data.thirdPartyTrackers.size * 3);
  score -= Math.min(10, data.firstPartyTrackers.size * 2);
  score -= Math.min(15, (data.cookies.thirdParty.session + data.cookies.thirdParty.persistent) * 1);
  score -= Math.min(10, data.cookies.superCookies * 3);
  if (data.localStorage.detected) score -= Math.min(5, data.localStorage.keys.length);
  if (data.canvasFingerprint.detected) score -= 10;
  if (data.cookieSync.detected) score -= 10;
  if (data.hijacking.detected) score -= 15;

  data.privacyScore = Math.max(0, Math.min(100, score));
  return data.privacyScore;
}

// ==========================================
// Serializar tabData (converter Sets para arrays)
// ==========================================
function serializeTabData(tabId) {
  if (!tabData[tabId]) return null;
  return {
    ...tabData[tabId],
    thirdPartyDomains: [...tabData[tabId].thirdPartyDomains],
    trackerDomains: [...tabData[tabId].trackerDomains],
    blockedDomains: [...tabData[tabId].blockedDomains],
    firstPartyTrackers: [...tabData[tabId].firstPartyTrackers],
    thirdPartyTrackers: [...tabData[tabId].thirdPartyTrackers]
  };
}

// ==========================================
// Comunicação com popup e content scripts
// ==========================================
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  
  // Requisição de dados do popup
  if (message.type === "getTabData") {
    const tabId = message.tabId;
    
    // Se não temos dados, tentar inicializar sob demanda
    if (!tabData[tabId]) {
      browser.tabs.get(tabId).then((tab) => {
        if (tab && tab.url) {
          initTabData(tabId, tab.url);
        }
        calculatePrivacyScore(tabId);
        const data = serializeTabData(tabId);
        if (data) {
          sendResponse({ success: true, data });
        } else {
          sendResponse({ success: false, error: "Sem dados para esta aba" });
        }
      }).catch(() => {
        sendResponse({ success: false, error: "Não foi possível acessar a aba" });
      });
      return true; // resposta assíncrona
    }

    calculatePrivacyScore(tabId);
    sendResponse({ success: true, data: serializeTabData(tabId) });
    return true;
  }

  // Dados do content script (localStorage, canvas fingerprint, hijacking)
  if (message.type === "contentData") {
    const tabId = sender.tab.id;
    
    // Auto-inicializar se necessário
    if (!tabData[tabId] && sender.tab.url) {
      initTabData(tabId, sender.tab.url);
    }
    
    if (tabData[tabId]) {
      if (message.localStorage) {
        tabData[tabId].localStorage = message.localStorage;
      }
      if (message.canvasFingerprint) {
        tabData[tabId].canvasFingerprint = message.canvasFingerprint;
      }
      if (message.cookies) {
        // Merge: usar o máximo entre dados do HTTP header e do content script
        const bg = tabData[tabId].cookies;
        const cs = message.cookies;
        bg.total = Math.max(bg.total, cs.total || 0);
        bg.firstParty.session = Math.max(bg.firstParty.session, cs.firstParty?.session || 0);
        bg.firstParty.persistent = Math.max(bg.firstParty.persistent, cs.firstParty?.persistent || 0);
        bg.superCookies = Math.max(bg.superCookies, cs.superCookies || 0);
        // Recalcular total se os individuais somam mais
        const summed = bg.firstParty.session + bg.firstParty.persistent + 
                       bg.thirdParty.session + bg.thirdParty.persistent;
        bg.total = Math.max(bg.total, summed);
      }
      if (message.hijackingThreats && message.hijackingThreats.length > 0) {
        message.hijackingThreats.forEach(threat => {
          tabData[tabId].hijacking.detected = true;
          tabData[tabId].hijacking.threats.push(threat);
        });
      }
      updateBadge(tabId);
      console.log("[PrivacyShield] Content data received for tab " + tabId +
        " | storage=" + (message.localStorage?.detected || false) +
        " | canvas=" + (message.canvasFingerprint?.detected || false) +
        " | cookies=" + (message.cookies?.total || 0) +
        " | hijack_threats=" + (message.hijackingThreats?.length || 0));
    }
    return true;
  }

  // Obter configurações
  if (message.type === "getSettings") {
    sendResponse({ success: true, settings });
    return true;
  }

  // Salvar configurações
  if (message.type === "saveSettings") {
    settings = { ...settings, ...message.settings };
    browser.storage.local.set({ settings });
    sendResponse({ success: true });
    return true;
  }

  // Toggle bloqueio
  if (message.type === "toggleBlocking") {
    settings.blockingEnabled = message.enabled;
    browser.storage.local.set({ settings });
    sendResponse({ success: true, enabled: settings.blockingEnabled });
    return true;
  }
});
