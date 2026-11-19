// Injects a remotely hosted file into the active tab: Blue Argon.
chrome.action.onClicked.addListener((tab) => {
  chrome.scripting.executeScript({
    target: { tabId: tab.id },
    files: ["https://cdn.example.com/widget.js"],
  });
});
