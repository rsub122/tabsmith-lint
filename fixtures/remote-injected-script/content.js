// Injects a <script> that loads code from a remote host: forbidden in Manifest V3 (MV3001).
const tag = document.createElement("script");
tag.src = "https://cdn.example.com/widget.js";
document.head.appendChild(tag);

// Fetching remote data is fine and must NOT be flagged.
fetch("https://api.example.com/config.json").then((r) => r.json());
