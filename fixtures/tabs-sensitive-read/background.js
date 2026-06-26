chrome.tabs.query({ active: true }, (tabs) => {
  const tab = tabs[0];
  console.log(tab.url, tab.title);
});
