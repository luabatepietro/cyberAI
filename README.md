# Detector de Rastreadores

**Extensão para Firefox** desenvolvida para a disciplina de Cybersegurança do Insper.

## Como Instalar no Firefox

### Método 1: Instalação Temporária (para desenvolvimento/teste)

1. Abra o Firefox
2. Digite `about:debugging` na barra de endereço
3. Clique em **"Este Firefox"** (ou "This Firefox")
4. Clique em **"Carregar extensão temporária..."** (ou "Load Temporary Add-on...")
5. Navegue até a pasta da extensão e selecione o arquivo `manifest.json`
6. A extensão aparecerá no canto superior direito do navegador com o ícone de escudo

> Extensões temporárias são removidas ao fechar o Firefox. Para uso permanente, use o Método 2.

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
