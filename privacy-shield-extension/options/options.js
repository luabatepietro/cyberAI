/**
 * Privacy Shield - Options Page Script
 * Gerencia configurações, listas de bloqueio e whitelist
 */

document.addEventListener("DOMContentLoaded", () => {
  let currentSettings = {
    blockingEnabled: true,
    showNotifications: true,
    customBlocklist: [],
    customWhitelist: []
  };

  // Carregar configurações
  loadSettings();

  // ==========================================
  // Carregar configurações do storage
  // ==========================================
  function loadSettings() {
    browser.runtime.sendMessage({ type: "getSettings" }).then((response) => {
      if (response && response.success) {
        currentSettings = { ...currentSettings, ...response.settings };
        renderSettings();
      }
    });
  }

  function renderSettings() {
    document.getElementById("blockingEnabled").checked = currentSettings.blockingEnabled;
    document.getElementById("showNotifications").checked = currentSettings.showNotifications;
    renderList("blocklistContainer", currentSettings.customBlocklist, "blocklist");
    renderList("whitelistContainer", currentSettings.customWhitelist, "whitelist");
  }

  // ==========================================
  // Renderizar listas
  // ==========================================
  function renderList(containerId, items, listType) {
    const container = document.getElementById(containerId);
    
    if (items.length === 0) {
      container.innerHTML = `<div class="empty-state">${
        listType === "blocklist" 
          ? "Nenhum domínio personalizado na lista de bloqueio." 
          : "Nenhum domínio na lista de permissão."
      }</div>`;
      return;
    }

    container.innerHTML = "";
    items.forEach((domain, index) => {
      const item = document.createElement("div");
      item.className = "list-item";
      item.innerHTML = `
        <span>${domain}</span>
        <button class="btn btn-danger btn-small" data-list="${listType}" data-index="${index}">✕ Remover</button>
      `;
      container.appendChild(item);
    });

    // Event listeners para botões de remover
    container.querySelectorAll("button").forEach((btn) => {
      btn.addEventListener("click", () => {
        const list = btn.dataset.list;
        const index = parseInt(btn.dataset.index);
        if (list === "blocklist") {
          currentSettings.customBlocklist.splice(index, 1);
        } else {
          currentSettings.customWhitelist.splice(index, 1);
        }
        renderSettings();
      });
    });
  }

  // ==========================================
  // Adicionar domínio
  // ==========================================
  function addDomain(inputId, listKey) {
    const input = document.getElementById(inputId);
    let domain = input.value.trim().toLowerCase();
    
    if (!domain) return;

    // Limpar protocolo se inserido
    domain = domain.replace(/^https?:\/\//, "").replace(/\/.*$/, "");

    // Validar formato
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) {
      input.style.borderColor = "#e74c3c";
      setTimeout(() => { input.style.borderColor = "#e9ecef"; }, 2000);
      return;
    }

    // Verificar duplicata
    if (currentSettings[listKey].includes(domain)) {
      input.style.borderColor = "#f39c12";
      setTimeout(() => { input.style.borderColor = "#e9ecef"; }, 2000);
      return;
    }

    currentSettings[listKey].push(domain);
    input.value = "";
    renderSettings();
  }

  document.getElementById("addBlocklist").addEventListener("click", () => {
    addDomain("blocklistInput", "customBlocklist");
  });

  document.getElementById("addWhitelist").addEventListener("click", () => {
    addDomain("whitelistInput", "customWhitelist");
  });

  // Enter para adicionar
  document.getElementById("blocklistInput").addEventListener("keydown", (e) => {
    if (e.key === "Enter") addDomain("blocklistInput", "customBlocklist");
  });

  document.getElementById("whitelistInput").addEventListener("keydown", (e) => {
    if (e.key === "Enter") addDomain("whitelistInput", "customWhitelist");
  });

  // ==========================================
  // Salvar configurações
  // ==========================================
  document.getElementById("saveBtn").addEventListener("click", () => {
    currentSettings.blockingEnabled = document.getElementById("blockingEnabled").checked;
    currentSettings.showNotifications = document.getElementById("showNotifications").checked;

    browser.runtime.sendMessage({
      type: "saveSettings",
      settings: currentSettings
    }).then((response) => {
      if (response && response.success) {
        const status = document.getElementById("saveStatus");
        status.textContent = "✅ Configurações salvas!";
        setTimeout(() => { status.textContent = ""; }, 3000);
      }
    });
  });
});
