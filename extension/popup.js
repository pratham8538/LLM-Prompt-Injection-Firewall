document.addEventListener('DOMContentLoaded', async () => {
  const serverUrlInput = document.getElementById('server-url');
  const enableToggle = document.getElementById('enable-toggle');
  const statusDot = document.getElementById('status-dot');
  const statusText = document.getElementById('status-text');
  const testBtn = document.getElementById('test-btn');
  const saveBtn = document.getElementById('save-btn');
  const blockedCountEl = document.getElementById('blocked-count');

  // Load saved settings
  const data = await chrome.storage.local.get(['firewallUrl', 'enabled', 'blockedCount']);
  if (data.firewallUrl) {
    serverUrlInput.value = data.firewallUrl;
  }
  if (data.enabled !== undefined) {
    enableToggle.checked = data.enabled;
  }
  blockedCountEl.textContent = data.blockedCount || 0;

  // Auto test on open
  checkHealth(serverUrlInput.value);

  // Toggle active
  enableToggle.addEventListener('change', async () => {
    await chrome.storage.local.set({ enabled: enableToggle.checked });
  });

  // Save button
  saveBtn.addEventListener('click', async () => {
    const url = serverUrlInput.value.trim().replace(/\/+$/, '');
    await chrome.storage.local.set({ firewallUrl: url });
    saveBtn.textContent = 'Saved!';
    setTimeout(() => { saveBtn.textContent = 'Save Configuration'; }, 1500);
    checkHealth(url);
  });

  // Test button
  testBtn.addEventListener('click', () => {
    checkHealth(serverUrlInput.value.trim().replace(/\/+$/, ''));
  });

  async function checkHealth(url) {
    statusText.textContent = 'Checking...';
    statusDot.className = 'status-dot';

    try {
      const res = await new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: 'TEST_CONNECTION', url }, resolve);
      });

      if (res && res.success && res.data && res.data.status === 'healthy') {
        statusDot.className = 'status-dot online';
        statusText.textContent = 'Connected (Online)';
      } else {
        statusDot.className = 'status-dot';
        statusText.textContent = 'Offline / Unreachable';
      }
    } catch (e) {
      statusDot.className = 'status-dot';
      statusText.textContent = 'Error connecting';
    }
  }
});
