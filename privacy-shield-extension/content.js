/**
 * Privacy Shield - Content Script
 * 
 * Executa no contexto da página para detectar:
 * - Uso de localStorage / sessionStorage (HTML5)
 * - Tentativas de Canvas Fingerprinting
 * - Potenciais ameaças de hijacking (hooks, iframes maliciosos)
 */

(function () {
  "use strict";

  const detections = {
    localStorage: {
      detected: false,
      keys: [],
      size: 0
    },
    canvasFingerprint: {
      detected: false,
      attempts: 0
    },
    hijackingThreats: [],
    cookies: {
      total: 0,
      firstParty: { session: 0, persistent: 0 },
      thirdParty: { session: 0, persistent: 0 },
      superCookies: 0,
      list: []
    }
  };

  // ==========================================
  // 1. Detecção de localStorage / sessionStorage
  // ==========================================
  function detectStorage() {
    detections.localStorage = { detected: false, keys: [], size: 0 };

    try {
      // Verificar localStorage
      if (window.localStorage && window.localStorage.length > 0) {
        detections.localStorage.detected = true;
        let totalSize = 0;

        for (let i = 0; i < window.localStorage.length; i++) {
          const key = window.localStorage.key(i);
          const value = window.localStorage.getItem(key);
          const size = (key.length + (value ? value.length : 0)) * 2;
          totalSize += size;
          detections.localStorage.keys.push({
            key: key,
            size: size,
            valuePreview: value ? value.substring(0, 50) + (value.length > 50 ? "..." : "") : ""
          });
        }
        detections.localStorage.size = totalSize;
      }

      // Verificar sessionStorage
      if (window.sessionStorage && window.sessionStorage.length > 0) {
        detections.localStorage.detected = true;
        for (let i = 0; i < window.sessionStorage.length; i++) {
          const key = window.sessionStorage.key(i);
          const value = window.sessionStorage.getItem(key);
          const size = (key.length + (value ? value.length : 0)) * 2;
          detections.localStorage.size += size;
          detections.localStorage.keys.push({
            key: "[session] " + key,
            size: size,
            valuePreview: value ? value.substring(0, 50) + (value.length > 50 ? "..." : "") : ""
          });
        }
      }

      // Verificar IndexedDB
      if (window.indexedDB && indexedDB.databases) {
        indexedDB.databases().then((dbs) => {
          if (dbs.length > 0) {
            detections.localStorage.detected = true;
            dbs.forEach((db) => {
              detections.localStorage.keys.push({
                key: "[IndexedDB] " + db.name,
                size: 0,
                valuePreview: "Banco de dados IndexedDB v" + db.version
              });
            });
            sendData();
          }
        }).catch(() => {});
      }
    } catch (e) {
      console.log("[PrivacyShield Content] Storage detection error:", e);
    }
  }

  // ==========================================
  // 2. Detecção de Canvas Fingerprinting
  // ==========================================
  function detectCanvasFingerprinting() {
    try {
      const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
      const originalToBlob = HTMLCanvasElement.prototype.toBlob;
      const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;

      HTMLCanvasElement.prototype.toDataURL = function () {
        if (this.width > 0 && this.height > 0 && this.width <= 500 && this.height <= 100) {
          detections.canvasFingerprint.detected = true;
          detections.canvasFingerprint.attempts++;
          console.log("[PrivacyShield Content] Canvas fingerprint detected via toDataURL");
          sendData();
        }
        return originalToDataURL.apply(this, arguments);
      };

      HTMLCanvasElement.prototype.toBlob = function () {
        if (this.width <= 500 && this.height <= 100 && this.width > 0) {
          detections.canvasFingerprint.detected = true;
          detections.canvasFingerprint.attempts++;
          sendData();
        }
        return originalToBlob.apply(this, arguments);
      };

      CanvasRenderingContext2D.prototype.getImageData = function () {
        if (this.canvas.width <= 500 && this.canvas.height <= 100 && this.canvas.width > 0) {
          detections.canvasFingerprint.detected = true;
          detections.canvasFingerprint.attempts++;
          sendData();
        }
        return originalGetImageData.apply(this, arguments);
      };
    } catch (e) {
      console.log("[PrivacyShield Content] Canvas detection setup error:", e);
    }
  }

  // ==========================================
  // 3. Detecção de Hijacking / Hooks
  // ==========================================
  function detectHijacking() {
    detections.hijackingThreats = [];

    // Verificar iframes ocultos suspeitos
    const iframes = document.querySelectorAll("iframe");
    iframes.forEach((iframe) => {
      if (!iframe.src) return;

      try {
        const iframeHost = new URL(iframe.src).hostname;
        const pageHost = window.location.hostname || "local-file";
        if (!iframeHost || iframeHost === pageHost) return;

        const style = window.getComputedStyle(iframe);
        const rect = iframe.getBoundingClientRect();
        const isHidden =
          style.display === "none" ||
          style.visibility === "hidden" ||
          rect.width <= 1 ||
          rect.height <= 1 ||
          style.opacity === "0" ||
          rect.top < -50;

        if (isHidden) {
          detections.hijackingThreats.push({
            type: "hidden_iframe",
            url: iframe.src,
            description: "iFrame oculto de terceiros: " + iframeHost
          });
        }
      } catch (e) {}
    });

    // Verificar se há frameworks de hook conhecidos
    if (typeof window.beef !== "undefined" || typeof window.BeEF !== "undefined") {
      detections.hijackingThreats.push({
        type: "beef_framework",
        description: "Framework BeEF detectado! Possível ataque de browser hooking."
      });
    }

    // Verificar scripts inline suspeitos
    const scripts = document.querySelectorAll("script:not([src])");
    scripts.forEach((script) => {
      const content = script.textContent || "";
      if (content.length > 10 && content.length < 500) {
        const suspicious = [
          /eval\s*\(/,
          /document\.write\s*\(/,
          /window\.location\s*=\s*['"]/,
          /\.createElement\s*\(\s*['"]script['"]\s*\)/
        ];
        if (suspicious.some((p) => p.test(content))) {
          detections.hijackingThreats.push({
            type: "suspicious_inline_script",
            description: "Script inline com padrão suspeito",
            preview: content.substring(0, 80) + "..."
          });
        }
      }
    });
  }

  // ==========================================
  // 4. Detecção de Cookies via JavaScript
  // ==========================================
  function detectCookies() {
    try {
      const cookieString = document.cookie;
      if (!cookieString) {
        detections.cookies.total = 0;
        return;
      }
      const cookies = cookieString.split(';').filter(c => c.trim());
      detections.cookies.total = cookies.length;
      detections.cookies.list = cookies.map(c => {
        const parts = c.trim().split('=');
        return { name: parts[0], value: (parts[1] || '').substring(0, 30) };
      });
      // Nota: via document.cookie não temos como saber expires ou 3rd party,
      // mas podemos contar o total. Classificaremos todos como 1st party session.
      detections.cookies.firstParty.session = cookies.length;
    } catch (e) {
      console.log("[PrivacyShield Content] Cookie detection error:", e);
    }
  }

  // Interceptar document.cookie setter para contar cookies em tempo real
  function interceptCookieSetter() {
    try {
      const originalDescriptor = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie') ||
                                  Object.getOwnPropertyDescriptor(HTMLDocument.prototype, 'cookie');
      if (!originalDescriptor) return;

      Object.defineProperty(document, 'cookie', {
        get: function() {
          return originalDescriptor.get.call(this);
        },
        set: function(value) {
          // Analisar o cookie sendo setado
          const lower = value.toLowerCase();
          const hasExpires = lower.includes('expires=') || lower.includes('max-age=');
          
          if (hasExpires) {
            detections.cookies.firstParty.persistent++;
            // Verificar supercookie
            const maxAgeMatch = lower.match(/max-age=(\d+)/);
            if (maxAgeMatch && parseInt(maxAgeMatch[1]) > 365 * 24 * 60 * 60) {
              detections.cookies.superCookies++;
            }
            const expiresMatch = lower.match(/expires=([^;]+)/);
            if (expiresMatch) {
              try {
                const exp = new Date(expiresMatch[1]);
                const diff = (exp - new Date()) / (1000 * 60 * 60 * 24 * 365);
                if (diff > 1) detections.cookies.superCookies++;
              } catch(e) {}
            }
            // Hash-like value = supercookie
            const cookieVal = (value.split('=')[1] || '').split(';')[0];
            if (/[a-f0-9]{32,}/i.test(cookieVal)) {
              detections.cookies.superCookies++;
            }
          } else {
            detections.cookies.firstParty.session++;
          }

          // Chamar o setter original
          return originalDescriptor.set.call(this, value);
        },
        configurable: true
      });
      console.log("[PrivacyShield Content] Cookie setter intercepted");
    } catch (e) {
      console.log("[PrivacyShield Content] Cookie intercept error:", e);
    }
  }

  // ==========================================
  // Enviar dados para o background script
  // ==========================================
  let sendAttempts = 0;
  
  function sendData() {
    try {
      browser.runtime.sendMessage({
        type: "contentData",
        localStorage: detections.localStorage,
        canvasFingerprint: detections.canvasFingerprint,
        hijackingThreats: detections.hijackingThreats,
        cookies: detections.cookies
      }).then(() => {
        console.log("[PrivacyShield Content] Data sent successfully");
      }).catch((err) => {
        console.log("[PrivacyShield Content] Send failed, will retry:", err);
        if (sendAttempts < 5) {
          sendAttempts++;
          setTimeout(sendData, 1000 * sendAttempts);
        }
      });
    } catch (e) {
      console.log("[PrivacyShield Content] sendMessage error:", e);
    }
  }

  // ==========================================
  // Observar mudanças no DOM (novos iframes, scripts)
  // ==========================================
  function observeDOM() {
    const observer = new MutationObserver((mutations) => {
      let needsRecheck = false;
      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (node.tagName === "IFRAME" || node.tagName === "SCRIPT") {
            needsRecheck = true;
            break;
          }
        }
        if (needsRecheck) break;
      }
      if (needsRecheck) {
        setTimeout(() => {
          detectHijacking();
          sendData();
        }, 500);
      }
    });

    observer.observe(document.documentElement, {
      childList: true,
      subtree: true
    });
  }

  // ==========================================
  // Inicialização
  // ==========================================
  function init() {
    console.log("[PrivacyShield Content] Initializing on", window.location.href);

    // Interceptar ANTES de outros scripts
    detectCanvasFingerprinting();
    interceptCookieSetter();

    // Função de scan completo
    function fullScan() {
      console.log("[PrivacyShield Content] Running full scan...");
      detectStorage();
      detectCookies();
      detectHijacking();
      sendData();
    }

    // Executar scan assim que possível
    if (document.readyState === "complete" || document.readyState === "interactive") {
      // Página já carregou: executar com pequeno delay para pegar dados de scripts
      setTimeout(fullScan, 500);
      // Segundo scan depois de mais tempo (pega scripts que inicializam devagar)
      setTimeout(fullScan, 3000);
    } else {
      window.addEventListener("load", () => {
        setTimeout(fullScan, 500);
        setTimeout(fullScan, 3000);
      });
    }

    // Observar DOM para novas inserções de iframes/scripts
    if (document.documentElement) {
      observeDOM();
    } else {
      document.addEventListener("DOMContentLoaded", observeDOM);
    }

    // Scan periódico para pegar mudanças dinâmicas
    setInterval(fullScan, 8000);
  }

  init();
})();
