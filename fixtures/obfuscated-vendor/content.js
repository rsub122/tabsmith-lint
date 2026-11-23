// First-party code is plain; the bundled vendor/price-helper.min.js is obfuscated.
chrome.storage.sync.get(["enabled"]).then((s) => {
  if (s.enabled) document.documentElement.dataset.prices = "on";
});
