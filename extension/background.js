/**
 * LLM Firewall - Background Service Worker
 * Proxies inspection requests from ChatGPT/web content scripts to the student laptop firewall.
 */

const DEFAULT_FIREWALL_URL = 'http://localhost:3000';

// Listen for messages from content scripts or popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'CHECK_PROMPT') {
    handlePromptInspection(request.prompt)
      .then((result) => sendResponse({ success: true, data: result }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true; // Keep channel open for async response
  }

  if (request.type === 'TEST_CONNECTION') {
    testFirewallConnection(request.url)
      .then((result) => sendResponse({ success: true, data: result }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }
});

async function getFirewallUrl() {
  const data = await chrome.storage.local.get(['firewallUrl', 'enabled']);
  return {
    url: (data.firewallUrl || DEFAULT_FIREWALL_URL).replace(/\/+$/, ''),
    enabled: data.enabled !== false,
  };
}

async function testFirewallConnection(customUrl) {
  const url = (customUrl || DEFAULT_FIREWALL_URL).replace(/\/+$/, '');
  const res = await fetch(`${url}/api/health`, { method: 'GET' });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return await res.json();
}

async function handlePromptInspection(prompt) {
  const { url, enabled } = await getFirewallUrl();

  if (!enabled) {
    return {
      firewallDecision: 'ALLOW',
      threatScore: 0,
      riskLevel: 'LOW',
      detections: [],
      note: 'Firewall extension currently disabled in settings',
    };
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 4000);

    const response = await fetch(`${url}/api/inspect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        prompt,
        client_ip: 'lab-pc-extension',
        metadata: { source: 'browser-extension-interceptor' },
      }),
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`Firewall returned HTTP ${response.status}`);
    }

    const data = await response.json();

    // Track total blocks in local storage for stats
    if (data.action === 'BLOCK' || data.firewallDecision === 'BLOCK') {
      const stats = await chrome.storage.local.get(['blockedCount']);
      const current = stats.blockedCount || 0;
      await chrome.storage.local.set({ blockedCount: current + 1 });
    }

    return data;
  } catch (error) {
    console.error('Failed to communicate with LLM Firewall:', error);
    // In fail-safe lab mode, report error so user knows the laptop is unreachable
    return {
      firewallDecision: 'BLOCK',
      threatScore: 99,
      riskLevel: 'CRITICAL',
      detections: [{
        ruleId: 'CONNECTION_OFFLINE',
        category: 'SYSTEM_ERROR',
        description: `Could not reach Laptop Firewall at ${url}. Ensure server.ts is running and connected to the same Wi-Fi / Lab network.`,
      }],
      unreachable: true,
      error: error.message,
    };
  }
}
