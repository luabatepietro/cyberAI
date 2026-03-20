# 🛡️ Privacy Shield - Detector de Rastreadores

**Extensão para Firefox** desenvolvida para a disciplina de Cybersegurança do Insper.

## 📦 Como Instalar no Firefox

### Método 1: Instalação Temporária (para desenvolvimento/teste)

1. Abra o Firefox
2. Digite `about:debugging` na barra de endereço
3. Clique em **"Este Firefox"** (ou "This Firefox")
4. Clique em **"Carregar extensão temporária..."** (ou "Load Temporary Add-on...")
5. Navegue até a pasta da extensão e selecione o arquivo `manifest.json`
6. A extensão aparecerá no canto superior direito do navegador com o ícone de escudo

> ⚠️ Extensões temporárias são removidas ao fechar o Firefox. Para uso permanente, use o Método 2.

### Método 2: Instalação via arquivo .zip

1. Abra o Firefox
2. Digite `about:debugging` na barra de endereço
3. Clique em **"Este Firefox"**
4. Clique em **"Carregar extensão temporária..."**
5. Selecione o arquivo `privacy-shield-extension.zip`

## 🏗️ Arquitetura da Extensão

```
privacy-shield-extension/
├── manifest.json          # Configuração principal da WebExtension
├── background.js          # Script de fundo (interceptação de requisições)
├── content.js             # Script de conteúdo (detecta localStorage, canvas, hijacking)
├── trackers.js            # Banco de dados de domínios rastreadores
├── popup/
│   ├── popup.html         # Interface principal (popup ao clicar no ícone)
│   ├── popup.css          # Estilos do popup
│   └── popup.js           # Lógica do popup
├── options/
│   ├── options.html       # Página de configurações
│   ├── options.css        # Estilos da página de configurações
│   └── options.js         # Lógica das configurações
└── icons/
    ├── icon-48.png        # Ícone 48x48
    └── icon-96.png        # Ícone 96x96
```

## ✅ Funcionalidades Implementadas

### Entregáveis Básicos (Nota C)
- [x] Conexões a domínios de terceira parte
- [x] Potenciais ameaças de hijacking e hook (BeEF, iframes ocultos, scripts suspeitos)
- [x] Armazenamento de dados (localStorage, sessionStorage, IndexedDB)
- [x] Cookies e supercookies (1ª vs 3ª parte, sessão vs persistente)
- [x] Detecção de Canvas Fingerprinting
- [x] Pontuação de privacidade (metodologia documentada)

### Interface e Relatório (Nota B)
- [x] Interface intuitiva via popup
- [x] Relatório visual de rastreadores bloqueados
- [x] Seções expandíveis com detalhes

### Personalização Avançada (Nota A)
- [x] Lista de bloqueio personalizada
- [x] Lista de permissão (whitelist)
- [x] Diferenciação entre rastreadores de 1ª e 3ª parte
- [x] Toggle de bloqueio on/off
- [x] Página de configurações completa

## 📊 Metodologia de Pontuação

| Critério                    | Penalidade         | Máximo  |
|-----------------------------|-------------------|---------|
| Rastreadores de 3ª parte    | -3 por rastreador | -30 pts |
| Rastreadores de 1ª parte    | -2 por rastreador | -10 pts |
| Cookies de 3ª parte         | -1 por cookie     | -15 pts |
| Supercookies                | -3 por supercookie| -10 pts |
| localStorage/sessionStorage | -1 por chave      | -5 pts  |
| Canvas Fingerprinting       | Detecção          | -10 pts |
| Sincronismo de Cookies      | Detecção          | -10 pts |
| Ameaças de Hijacking        | Detecção          | -15 pts |

**Classificação:** 80-100 (Excelente) | 60-79 (Moderada) | 40-59 (Baixa) | 0-39 (Crítica)

## 🔧 Tecnologias Utilizadas

- **WebExtensions API** (Manifest V2 para Firefox)
- **webRequest API** - Interceptação e bloqueio de requisições HTTP
- **cookies API** - Monitoramento de cookies
- **storage API** - Persistência de configurações
- **Content Scripts** - Injeção de código para detecção no contexto da página
- JavaScript puro (sem frameworks externos)

## 📚 Referências

- [MDN - Sua primeira WebExtension](https://developer.mozilla.org/pt-BR/docs/Mozilla/Add-ons/WebExtensions/sua_primeira_WebExtension)
- [EasyList / EasyPrivacy](https://easylist.to/)
- [Canvas Fingerprinting - fingerprintable.org](https://fingerprintable.org)
- [StoragErazor - GitHub](https://github.com/Miraculix200/StoragErazor)
