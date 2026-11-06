// Brands that get phished the most, worldwide and in the UK (Check Point
// brand phishing reports, NCSC, Which?), and the domains that are really
// theirs. `name` is the word attackers imitate.
//
// Anything else popular is covered by data/top-sites.json - this list is for
// brands that deserve "high" severity and need extra legitimate domains.
export const DEFAULT_BRANDS = [
  { label: "Microsoft", name: "microsoft", domains: ["microsoft.com", "microsoftonline.com", "live.com", "office.com", "outlook.com", "office365.com", "sharepoint.com", "onedrive.com", "msn.com", "mcas.ms", "azure.com", "windows.net"] },
  { label: "LinkedIn", name: "linkedin", domains: ["linkedin.com", "lnkd.in"] },
  { label: "Google", name: "google", domains: ["google.com", "google.co.uk", "googleapis.com", "googleusercontent.com", "gmail.com", "youtube.com"] },
  { label: "Apple", name: "apple", domains: ["apple.com", "icloud.com", "apple.news"] },
  // pcloud, xcloud, ecloud... are all real companies one letter away
  { label: "iCloud", name: "icloud", domains: ["icloud.com", "apple.com"], typos: false },
  { label: "Amazon", name: "amazon", domains: ["amazon.com", "amazon.co.uk", "amazonaws.com", "amazon.jobs", "amazontrust.com", "primevideo.com", "amazon.work", "amazon.dev", "a2z.com"] },
  { label: "PayPal", name: "paypal", domains: ["paypal.com", "paypal.me", "paypalobjects.com", "paypal-community.com"] },
  { label: "ChatGPT", name: "chatgpt", domains: ["chatgpt.com", "openai.com"] },
  { label: "OpenAI", name: "openai", domains: ["openai.com", "chatgpt.com"] },
  { label: "Netflix", name: "netflix", domains: ["netflix.com", "nflxext.com"] },
  { label: "Facebook", name: "facebook", domains: ["facebook.com", "fb.com", "facebookmail.com"] },
  { label: "Instagram", name: "instagram", domains: ["instagram.com"] },
  { label: "WhatsApp", name: "whatsapp", domains: ["whatsapp.com", "whatsapp.net"] },
  { label: "DocuSign", name: "docusign", domains: ["docusign.com", "docusign.net"] },
  { label: "Adobe", name: "adobe", domains: ["adobe.com", "adobelogin.com"] },
  { label: "Dropbox", name: "dropbox", domains: ["dropbox.com"] },
  { label: "eBay", name: "ebay", domains: ["ebay.com", "ebay.co.uk", "ebaystatic.com"] },
  { label: "Coinbase", name: "coinbase", domains: ["coinbase.com"] },
  { label: "Binance", name: "binance", domains: ["binance.com"] },
  { label: "Steam", name: "steamcommunity", domains: ["steamcommunity.com", "steampowered.com"] },
  // UK banks
  { label: "Barclays", name: "barclays", domains: ["barclays.co.uk", "barclays.com", "barclaycard.co.uk"] },
  { label: "HSBC", name: "hsbc", domains: ["hsbc.co.uk", "hsbc.com"] },
  { label: "Lloyds Bank", name: "lloydsbank", domains: ["lloydsbank.com", "lloydsbank.co.uk"] },
  { label: "Lloyds", name: "lloyds", domains: ["lloydsbank.com", "lloyds.com", "lloydsbankinggroup.com"] },
  { label: "NatWest", name: "natwest", domains: ["natwest.com"] },
  { label: "Santander", name: "santander", domains: ["santander.co.uk", "santander.com"] },
  // nationwide.com is the US insurer, a different company, but not a scam
  { label: "Nationwide", name: "nationwide", domains: ["nationwide.co.uk", "nationwide.com"] },
  { label: "Halifax", name: "halifax", domains: ["halifax.co.uk"] },
  { label: "Monzo", name: "monzo", domains: ["monzo.com", "monzo.me"] },
  { label: "Revolut", name: "revolut", domains: ["revolut.com", "revolut.me"] },
  // UK delivery
  { label: "Royal Mail", name: "royalmail", domains: ["royalmail.com", "royalmailgroup.com"] },
  { label: "Evri", name: "evri", domains: ["evri.com"] },
  { label: "DPD", name: "dpd", domains: ["dpd.co.uk", "dpd.com", "dpdlocal.co.uk"] },
  { label: "DHL", name: "dhl", domains: ["dhl.com", "dhl.co.uk"] },
  { label: "UPS", name: "ups", domains: ["ups.com"] },
  { label: "Post Office", name: "postoffice", domains: ["postoffice.co.uk"] },
  { label: "InPost", name: "inpost", domains: ["inpost.co.uk", "inpost.eu"] },
  // UK government (NCSC's most impersonated public bodies)
  { label: "GOV.UK", name: "govuk", domains: ["gov.uk"] },
  { label: "HMRC", name: "hmrc", domains: ["gov.uk", "hmrc.gov.uk"] },
  { label: "DVLA", name: "dvla", domains: ["gov.uk"] },
  { label: "NHS", name: "nhs", domains: ["nhs.uk", "nhs.net"] },
  { label: "TV Licensing", name: "tvlicensing", domains: ["tvlicensing.co.uk"] },
  { label: "Ofgem", name: "ofgem", domains: ["ofgem.gov.uk"] },
];

// Words scammers bolt onto a brand. The UK ones (redelivery, customs, toll,
// fine...) come from the parcel, tax-refund and fake-fine texts doing the
// rounds right now.
export const SCAM_WORDS = [
  "login", "signin", "logon", "secure", "security", "verify", "verification", "validate",
  "account", "update", "billing", "payment", "invoice", "support", "helpdesk",
  "wallet", "auth", "password", "reset", "unlock", "confirm", "suspend", "alert", "notice",
  "recover", "refund", "rebate", "claim", "redelivery", "delivery", "parcel", "package",
  "customs", "fee", "fine", "penalty", "toll", "tax", "track", "tracking", "reschedule", "reward",
  "prize", "gift", "bonus", "airdrop", "appeal",
];

// Services anyone can get a subdomain on that the Public Suffix List
// (data/platforms.json) doesn't cover. The part before the platform is chosen
// by whoever made the site, so it's treated as the site's own name.
export const EXTRA_PLATFORMS = [
  "wordpress.com", "weebly.com", "weeblysite.com", "000webhostapp.com", "godaddysites.com",
  "surge.sh", "filesusr.com", "*.web.core.windows.net", "ipfs.dweb.link", "ipns.dweb.link",
  "ipfs.w3s.link", "ipfs.nftstorage.link",
];

// Top sites whose name is an ordinary word (account.gov.uk, office.com).
// They're never treated as a brand inside another name.
export const GENERIC_WORDS = [
  "account", "accounts", "service", "services", "office", "online", "mail", "email", "news",
  "shop", "store", "bank", "banking", "pay", "app", "apps", "web", "cloud", "home", "portal",
  "my", "help", "info", "login", "secure", "support", "update", "verify", "wallet", "search",
  "games", "video", "music", "photo", "photos", "files", "drive", "docs", "live", "chat",
  "static", "mobile", "media", "cdn", "data", "global", "digital", "group", "world", "action",
  "link", "links", "free", "travel", "money", "cash", "market", "games", "sport", "sports",
];

// Hosts that serve content from millions of different people. Phishing
// feeds list some of them (a scam on Google Sites puts "sites.google.com" in
// the feed), so they can only ever be matched on the full URL.
export const SHARED_HOSTS = [
  "docs.google.com", "sites.google.com", "drive.google.com", "forms.gle",
  "storage.googleapis.com", "firebasestorage.googleapis.com", "script.google.com",
  "onedrive.live.com", "1drv.ms", "forms.office.com", "dropbox.com", "www.dropbox.com",
  "github.com", "raw.githubusercontent.com", "gitlab.com", "bit.ly", "tinyurl.com",
  "t.co", "linktr.ee", "canva.com", "www.canva.com", "ipfs.io", "cloudflare-ipfs.com",
  "gateway.pinata.cloud",
];

// Endings with far more phishing than their size would suggest (Interisle
// Phishing Landscape reports) plus .zip/.mov, which look like file names.
export const RISKY_TLDS = [
  "zip", "mov", "top", "xin", "bond", "cfd", "win", "help", "sbs", "icu", "cyou",
  "click", "link", "rest", "lat", "buzz", "cam",
];
