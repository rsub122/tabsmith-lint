// Fetching remote JSON/data is fine and must not be flagged.
fetch("https://api.example.com/data.json").then((r) => r.json()).then(console.log);
