# Detector de Rastreadores

**Extensão para Firefox** desenvolvida para a disciplina de Cybersegurança do Insper.
**Feito por: Lucas Abatepietro e Marcelo Alonso**

## O que é o Olha Malandro?

Olha Malandro é uma extensão para Firefox que monitora e protege sua privacidade 
enquanto você navega. Em tempo real, ela analisa cada página visitada e te mostra 
o que está acontecendo nos bastidores.

### O que ela detecta e faz:

1. **Rastreadores de 3ª parte** — identifica (e pode bloquear) domínios de publicidade, analytics e redes sociais carregados pela página sem você saber *(Conceito C)*
2. **Cookies** — classifica todos os cookies encontrados: 1ª/3ª parte, sessão/persistente e supercookies (cookies com expiração anormalmente longa) *(Conceito C)*
3. **Canvas Fingerprinting** — detecta quando sites tentam criar uma "impressão digital" do seu navegador usando a API Canvas *(Conceito C)*
4. **localStorage / sessionStorage / IndexedDB** — monitora dados que sites armazenam localmente no seu navegador *(Conceito C)*
5. **Cookie Syncing** — identifica quando rastreadores trocam identificadores entre si para te seguir em múltiplos sites *(Conceito C)*
6. **Ameaças de Hijacking** — detecta iframes ocultos, scripts suspeitos e redirecionamentos maliciosos *(Conceito C)*
7. **Pontuação de Privacidade (0–100)** — resume tudo isso em um score visual que indica o quão invasiva é a página atual *(Conceito C)*
8. **Interface de gerenciamento + relatório visual** — popup expansível com detalhes por categoria e botão de relatório completo *(Conceito B)*
9. **Listas personalizadas de bloqueio e whitelist** — o usuário pode adicionar ou proteger domínios manualmente *(Conceito A)*
10. **Diferenciação de rastreadores de 1ª e 3ª parte** — classifica e exibe separadamente rastreadores próprios do site e externos *(Conceito A)*

## Como Instalar no Firefox

### Método 1: Instalação Temporária (para desenvolvimento/teste)

1. Abra o Firefox
2. Digite `about:debugging` na barra de endereço
3. Clique em **"Este Firefox"** (ou "This Firefox")
4. Clique em **"Carregar extensão temporária..."** (ou "Load Temporary Add-on...")
5. Navegue até a pasta da extensão e selecione o arquivo `manifest.json`
6. A extensão aparecerá no canto superior direito do navegador com o ícone de escudo

### Método 2: Instalação via arquivo .zip

1. Abra o Firefox
2. Digite `about:debugging` na barra de endereço
3. Clique em **"Este Firefox"**
4. Clique em **"Carregar extensão temporária..."**
5. Selecione o arquivo `privacy-shield-extension.zip`

## Arquitetura da Extensão

```
privacy-shield-extension/
├── manifest.json          
├── background.js        
├── content.js         
├── trackers.js          
├── popup/
│   ├── popup.html        
│   ├── popup.css          
│   └── popup.js           
├── options/
│   ├── options.html      
│   ├── options.css     
│   └── options.js     
└── icons/
    ├── icon-48.png      
    └── icon-96.png       
```


##  Referências

- [MDN - Sua primeira WebExtension](https://developer.mozilla.org/pt-BR/docs/Mozilla/Add-ons/WebExtensions/sua_primeira_WebExtension)
- [EasyList / EasyPrivacy](https://easylist.to/)
- [Canvas Fingerprinting - fingerprintable.org](https://fingerprintable.org)
- [StoragErazor - GitHub](https://github.com/Miraculix200/StoragErazor)
