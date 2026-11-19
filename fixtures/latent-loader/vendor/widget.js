/*! acme-widget v2.4.1 | MIT */
// Shared website-widget code bundled into the extension. The extension never
// enables the recorder, but the loader below could fetch it from a CDN.
var RECORDER_URL = "https://cdn.acme-widget.example/recorder/rrweb.min.js";
function loadRecorder(url) {
  var s = document.createElement("script");
  s.src = url || RECORDER_URL;
  document.head.appendChild(s);
}
function initWidget(opts) {
  if (opts && opts.record) loadRecorder(opts.recorderUrl);
  return fetch("https://api.acme-widget.example/v1/config.json").then(function (r) { return r.json(); });
}
initWidget({});
