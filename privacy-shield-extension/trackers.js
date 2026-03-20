/**
 * Lista de domínios de rastreamento conhecidos
 * Baseada em listas públicas como EasyList/EasyPrivacy
 * Categorizada por tipo de rastreador
 */

const TRACKER_DATABASE = {
  // Rastreadores de anúncios (advertising)
  advertising: [
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "google-analytics.com",
    "googletagmanager.com",
    "googletagservices.com",
    "adnxs.com",
    "adsrvr.org",
    "adform.net",
    "advertising.com",
    "adcolony.com",
    "admob.com",
    "adskeeper.co.uk",
    "adtechus.com",
    "criteo.com",
    "criteo.net",
    "casalemedia.com",
    "media.net",
    "mediaplex.com",
    "outbrain.com",
    "taboola.com",
    "revcontent.com",
    "mgid.com",
    "zedo.com",
    "yieldmanager.com",
    "bidswitch.net",
    "openx.net",
    "pubmatic.com",
    "rubiconproject.com",
    "smartadserver.com",
    "sovrn.com",
    "spotxchange.com",
    "contextweb.com",
    "indexexchange.com",
    "lijit.com",
    "mathtag.com",
    "moatads.com",
    "serving-sys.com",
    "sharethrough.com",
    "tribalfusion.com",
    "turn.com",
    "undertone.com",
    "yieldmo.com"
  ],

  // Rastreadores de analytics
  analytics: [
    "google-analytics.com",
    "analytics.google.com",
    "hotjar.com",
    "mixpanel.com",
    "amplitude.com",
    "segment.io",
    "segment.com",
    "heapanalytics.com",
    "fullstory.com",
    "mouseflow.com",
    "crazyegg.com",
    "clicktale.net",
    "luckyorange.com",
    "inspectlet.com",
    "chartbeat.com",
    "chartbeat.net",
    "newrelic.com",
    "nr-data.net",
    "omtrdc.net",
    "demdex.net",
    "omniture.com",
    "kissmetrics.com",
    "keen.io",
    "woopra.com",
    "piwik.pro",
    "matomo.cloud",
    "statcounter.com",
    "clicky.com",
    "quantserve.com",
    "scorecardresearch.com",
    "comscore.com",
    "alexametrics.com"
  ],

  // Rastreadores de redes sociais
  social: [
    "facebook.net",
    "facebook.com",
    "fbcdn.net",
    "connect.facebook.net",
    "twitter.com",
    "platform.twitter.com",
    "t.co",
    "linkedin.com",
    "platform.linkedin.com",
    "snap.licdn.com",
    "pinterest.com",
    "assets.pinterest.com",
    "tiktok.com",
    "analytics.tiktok.com",
    "reddit.com",
    "redditstatic.com",
    "instagram.com"
  ],

  // Fingerprinting e tracking avançado
  fingerprinting: [
    "fingerprintjs.com",
    "cdn.jsdelivr.net",
    "iovation.com",
    "threatmetrix.com",
    "maxmind.com",
    "bluecava.com",
    "canvas-fingerprint.com",
    "deviceinfo.me",
    "browserleaks.com"
  ],

  // CDNs e serviços que podem rastrear
  cdn_tracking: [
    "cloudflare-insights.com",
    "cdn.mxpnl.com",
    "cdn.heapanalytics.com",
    "cdn.segment.com"
  ]
};

// Criar um Set com todos os domínios para busca rápida
const ALL_TRACKER_DOMAINS = new Set();
const TRACKER_CATEGORIES = {};

for (const [category, domains] of Object.entries(TRACKER_DATABASE)) {
  for (const domain of domains) {
    ALL_TRACKER_DOMAINS.add(domain);
    TRACKER_CATEGORIES[domain] = category;
  }
}

/**
 * Verifica se um hostname pertence a um domínio rastreador
 * Faz matching por sufixo para pegar subdomínios
 */
function isTrackerDomain(hostname) {
  if (ALL_TRACKER_DOMAINS.has(hostname)) return true;
  for (const tracker of ALL_TRACKER_DOMAINS) {
    if (hostname.endsWith("." + tracker)) return true;
  }
  return false;
}

/**
 * Retorna a categoria de um domínio rastreador
 */
function getTrackerCategory(hostname) {
  if (TRACKER_CATEGORIES[hostname]) return TRACKER_CATEGORIES[hostname];
  for (const tracker of ALL_TRACKER_DOMAINS) {
    if (hostname.endsWith("." + tracker)) return TRACKER_CATEGORIES[tracker];
  }
  return "unknown";
}
