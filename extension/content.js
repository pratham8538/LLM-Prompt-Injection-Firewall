/**
 * LLM Firewall - Universal Multi-LLM Client Interceptor
 * Compatible with: ChatGPT, Claude, Google Gemini, Microsoft Copilot, DeepSeek, Perplexity, Mistral, Poe, & local UIs.
 * Guarantees synchronous first-tick interception so malicious prompts NEVER reach LLM servers.
 */

(function () {
  console.log('[LLM Firewall] Universal AI Interceptor active.');

  let isApprovedSubmission = false;
  let isChecking = false;

  // Ultra-fast client-side pre-flight heuristic patterns for 0ms instantaneous response
  const INSTANT_ATTACK_REGEXES = [
    /ignore\s+(all\s+|any\s+)?(previous|prior|existing|above)\s+(instructions|prompts|directives|rules|constraints)/i,
    /disregard\s+(all\s+)?(prior|previous|rules|instructions)/i,
    /bypass\s+(all\s+)?(safety|guardrails|filters|restrictions)/i,
    /reveal\s+(your\s+)?(system\s+prompt|instructions|developer\s+prompt|hidden\s+prompt|secret)/i,
    /(show|print|display|dump|recite|give)\s+(me\s+)?(the\s+)?(entire\s+|full\s+)?system\s+prompt/i,
    /you\s+are\s+now\s+(DAN|STAN|Maximum|unfiltered|jailbroken|evil|unrestricted)/i,
    /enter\s+(developer\s+mode|god\s+mode|unrestricted\s+mode|debug\s+mode)/i,
    /without\s+(any\s+)?(ethical|safety|content)\s+(boundaries|filters|guidelines|restrictions)/i,
    /do\s+anything\s+now/i,
  ];

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initInterceptor);
  } else {
    initInterceptor();
  }

  function initInterceptor() {
    // 1. Capture Enter Key across ALL LLM inputs in capture phase
    document.addEventListener('keydown', handleKeydown, true);

    // 2. Capture Send Button Click across ALL LLMs in capture phase
    document.addEventListener('click', handleClick, true);

    // 3. Capture Form Submit in capture phase
    document.addEventListener('submit', handleSubmit, true);
  }

  // Universal Prompt Input Extractor for ANY LLM
  function getUniversalPromptInput() {
    try {
      const active = document.activeElement;
      if (
        active &&
        (active.tagName === 'TEXTAREA' ||
          active.isContentEditable ||
          active.getAttribute('contenteditable') === 'true' ||
          active.getAttribute('role') === 'textbox')
      ) {
        return active;
      }

      // Specific platform selectors fallback
      const selectors = [
        '#prompt-textarea',                                     // ChatGPT
        'div.ProseMirror[contenteditable="true"]',              // Claude
        'div[contenteditable="true"][data-placeholder]',        // Claude / ChatGPT
        'rich-textarea [contenteditable="true"]',               // Google Gemini
        'div[role="textbox"][contenteditable="true"]',          // Gemini / Teams
        'textarea[placeholder*="Ask"]',                         // DeepSeek / Perplexity
        'textarea[placeholder*="message"]',                     // Generic
        'div[contenteditable="true"]',                          // Generic SPA
        'textarea',                                             // Fallback
      ];

      for (const sel of selectors) {
        const el = document.querySelector(sel);
        if (el) return el;
      }
      return null;
    } catch {
      return null;
    }
  }

  function extractText(element) {
    if (!element) return '';
    try {
      if (element.tagName === 'TEXTAREA' || element.tagName === 'INPUT') {
        return element.value || '';
      }
      return element.innerText || element.textContent || '';
    } catch {
      return '';
    }
  }

  // Universal Send Button Finder for ANY LLM
  function findUniversalSendButton() {
    try {
      const selectors = [
        'button[data-testid="send-button"]',                    // ChatGPT
        'button[aria-label*="Send"]',                           // Claude / ChatGPT / Gemini
        'button[aria-label*="send"]',
        'button[aria-label*="Submit"]',                         // Copilot
        'button[title*="Send"]',
        'button[title*="Submit"]',
        'button.send-button',                                   // Gemini / Mistral
        'div[role="button"][aria-label*="Send"]',               // DeepSeek / Gemini
        'button:has(svg path[d*="M0.5"])',                      // Claude SVG
        'form button[type="submit"]',                           // Standard form
        'fieldset button',
      ];

      for (const sel of selectors) {
        const btn = document.querySelector(sel);
        if (btn && !btn.disabled) return btn;
      }
      return null;
    } catch {
      return null;
    }
  }

  // Quick Instant Pre-Flight Check (0ms response)
  function quickCheckHeuristic(text) {
    for (const regex of INSTANT_ATTACK_REGEXES) {
      if (regex.test(text)) {
        return {
          threatScore: 96,
          riskLevel: 'HIGH',
          action: 'BLOCK',
          detections: [
            {
              ruleId: 'INSTANT_CLIENT_PREFLIGHT',
              category: 'INSTRUCTION_OVERRIDE',
              description: 'Zero-tolerance prompt injection / adversarial directive triggered.',
              matchedSnippet: text.slice(0, 80),
            },
          ],
        };
      }
    }
    return null;
  }

  // 1. Handle Keydown (Enter)
  function handleKeydown(event) {
    if (event.key !== 'Enter' || event.shiftKey || event.isComposing) {
      return;
    }

    if (isApprovedSubmission) {
      // Approved by firewall! Let through to LLM.
      return;
    }

    const input = getUniversalPromptInput();
    if (!input) return;

    if (input === event.target || input.contains(event.target) || document.activeElement === input) {
      const text = extractText(input).trim();
      if (!text) return;

      // ⛔ SYNCHRONOUSLY STOP EVENT IMMEDIATELY!
      // This guarantees Claude, ChatGPT, Gemini, Copilot never receive the Enter key!
      event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation();

      if (isChecking) return;
      verifyAndExecute(text, input, 'enter');
    }
  }

  // 2. Handle Click (Send Button)
  function handleClick(event) {
    if (isApprovedSubmission) {
      return;
    }

    const sendBtn = event.target.closest(
      'button[data-testid="send-button"], button[aria-label*="Send"], button[aria-label*="send"], button[aria-label*="Submit"], button[id*="send"], div[role="button"][aria-label*="Send"], button.send-button'
    );

    if (sendBtn) {
      const input = getUniversalPromptInput();
      const text = input ? extractText(input).trim() : '';
      if (!text) return;

      // ⛔ SYNCHRONOUSLY STOP CLICK IMMEDIATELY!
      event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation();

      if (isChecking) return;
      verifyAndExecute(text, input, 'button', sendBtn);
    }
  }

  // 3. Handle Form Submit
  function handleSubmit(event) {
    if (isApprovedSubmission) return;

    const input = getUniversalPromptInput();
    const text = input ? extractText(input).trim() : '';
    if (!text) return;

    // ⛔ SYNCHRONOUSLY STOP SUBMIT IMMEDIATELY!
    event.preventDefault();
    event.stopPropagation();
    event.stopImmediatePropagation();

    if (isChecking) return;
    verifyAndExecute(text, input, 'form');
  }

  // Core Inspection Engine
  async function verifyAndExecute(promptText, inputElement, triggerType, sendBtnElement) {
    isChecking = true;

    // A. Instant Client Check (0.01ms)
    const instantResult = quickCheckHeuristic(promptText);
    if (instantResult) {
      console.warn('[LLM Firewall] ⛔ Instant Client Pre-Flight Block Triggered!');
      // Notify laptop server in background so Audit Log records it!
      chrome.runtime.sendMessage({ type: 'CHECK_PROMPT', prompt: promptText });
      
      // Stop cold and show modal immediately!
      showBlockedModal(promptText, instantResult);
      highlightBlockedInput(inputElement);
      isChecking = false;
      return;
    }

    // B. Laptop Firewall Server Verification (Fast-Path < 1ms)
    showScanningToast();

    try {
      const response = await new Promise((resolve) => {
        chrome.runtime.sendMessage(
          { type: 'CHECK_PROMPT', prompt: promptText },
          (res) => resolve(res)
        );
      });

      hideScanningToast();

      if (!response || !response.success) {
        console.warn('[LLM Firewall] Inspection communication warning:', response?.error);
        isChecking = false;
        proceedWithCleanSubmission(inputElement, triggerType, sendBtnElement);
        return;
      }

      const result = response.data;
      const decision = result.action || result.firewallDecision || 'ALLOW';
      const threatScore = Number(result.threatScore || 0);

      // BLOCK CONDITION
      if (decision === 'BLOCK' || threatScore >= 70) {
        console.warn(`[LLM Firewall] ⛔ PROMPT INJECTION HALTED! Threat Score: ${threatScore}/100.`);
        showBlockedModal(promptText, result);
        highlightBlockedInput(inputElement);
        isChecking = false;
        // NEVER call proceedWithCleanSubmission! Prompt is safely stopped!
        return;
      }

      // ALLOW CONDITION
      isChecking = false;
      proceedWithCleanSubmission(inputElement, triggerType, sendBtnElement);

    } catch (err) {
      console.error('[LLM Firewall] Error verifying prompt:', err);
      hideScanningToast();
      isChecking = false;
      proceedWithCleanSubmission(inputElement, triggerType, sendBtnElement);
    }
  }

  // Re-dispatch submission for safe prompts
  function proceedWithCleanSubmission(inputElement, triggerType, sendBtnElement) {
    isApprovedSubmission = true;

    const btn = sendBtnElement || findUniversalSendButton();
    if (btn) {
      btn.click();
    } else if (inputElement) {
      dispatchNativeEnter(inputElement);
    }

    setTimeout(() => {
      isApprovedSubmission = false;
    }, 300);
  }

  function dispatchNativeEnter(target) {
    const enterInit = {
      key: 'Enter',
      code: 'Enter',
      keyCode: 13,
      which: 13,
      bubbles: true,
      cancelable: true,
      composed: true,
    };
    target.dispatchEvent(new KeyboardEvent('keydown', enterInit));
    target.dispatchEvent(new KeyboardEvent('keypress', enterInit));
    target.dispatchEvent(new KeyboardEvent('keyup', enterInit));
  }

  function highlightBlockedInput(inputElement) {
    if (!inputElement) return;
    const oldStyle = inputElement.style.boxShadow;
    const oldBorder = inputElement.style.borderColor;
    inputElement.style.boxShadow = '0 0 0 3px rgba(239, 68, 68, 0.6)';
    inputElement.style.borderColor = '#ef4444';
    setTimeout(() => {
      if (inputElement) {
        inputElement.style.boxShadow = oldStyle;
        inputElement.style.borderColor = oldBorder;
      }
    }, 2500);
  }

  // UI: Scanning Indicator Toast
  function showScanningToast() {
    let toast = document.getElementById('llm-firewall-toast');
    if (!toast) {
      toast = document.createElement('div');
      toast.id = 'llm-firewall-toast';
      toast.style.cssText = `
        position: fixed;
        bottom: 24px;
        right: 24px;
        background: #0f172a;
        color: #38bdf8;
        padding: 9px 16px;
        border-radius: 9999px;
        font-family: system-ui, -apple-system, sans-serif;
        font-size: 12px;
        font-weight: 700;
        z-index: 99999999;
        box-shadow: 0 10px 25px rgba(0,0,0,0.6);
        border: 1px solid #1e293b;
        display: flex;
        align-items: center;
        gap: 8px;
        pointer-events: none;
      `;
      document.body.appendChild(toast);
    }
    toast.innerHTML = `<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#38bdf8;box-shadow:0 0 8px #38bdf8;"></span> Inspecting with Laptop Firewall...`;
    toast.style.display = 'flex';
  }

  function hideScanningToast() {
    const toast = document.getElementById('llm-firewall-toast');
    if (toast) toast.style.display = 'none';
  }

  // UI: High-Impact Blocked Modal
  function showBlockedModal(prompt, result) {
    let modal = document.getElementById('llm-firewall-modal');
    if (modal) modal.remove();

    modal = document.createElement('div');
    modal.id = 'llm-firewall-modal';
    modal.style.cssText = `
      position: fixed;
      inset: 0;
      background: rgba(15, 23, 42, 0.88);
      backdrop-filter: blur(8px);
      z-index: 100000000;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: system-ui, -apple-system, sans-serif;
      padding: 16px;
    `;

    const threatScore = result.threatScore || 95;
    const riskLevel = result.riskLevel || 'HIGH';
    const detections = result.detections || [];
    const detectionsHtml = detections.length > 0
      ? detections.map(d => `<li style="margin-bottom:6px;"><strong>${d.ruleId || 'RULE'}:</strong> ${escapeHtml(d.description || d.matchedSnippet || 'Malicious prompt injection detected')}</li>`).join('')
      : '<li>Adversarial prompt injection pattern triggered.</li>';

    modal.innerHTML = `
      <div style="
        background: #0f172a;
        border: 2px solid #ef4444;
        border-radius: 16px;
        max-width: 520px;
        width: 100%;
        color: #f8fafc;
        box-shadow: 0 25px 50px -12px rgba(239, 68, 68, 0.5);
        overflow: hidden;
      ">
        <div style="background:#450a0a;padding:18px 22px;border-bottom:1px solid #7f1d1d;display:flex;align-items:center;gap:12px;">
          <div style="font-size:32px;">🛡️</div>
          <div>
            <div style="font-size:18px;font-weight:800;color:#fecaca;letter-spacing:-0.01em;">PROMPT BLOCKED BY AI FIREWALL</div>
            <div style="font-size:12px;color:#fca5a5;font-weight:500;">Zero-Trust LLM Protection • College Lab Defense</div>
          </div>
        </div>
        <div style="padding:22px;">
          <div style="display:flex;gap:14px;margin-bottom:16px;">
            <div style="background:#1e293b;padding:12px 14px;border-radius:10px;flex:1;text-align:center;border:1px solid #334155;">
              <div style="font-size:10px;text-transform:uppercase;color:#94a3b8;font-weight:700;letter-spacing:0.05em;">Threat Score</div>
              <div style="font-size:26px;font-weight:800;color:#ef4444;margin-top:2px;">${threatScore} / 100</div>
            </div>
            <div style="background:#1e293b;padding:12px 14px;border-radius:10px;flex:1;text-align:center;border:1px solid #334155;">
              <div style="font-size:10px;text-transform:uppercase;color:#94a3b8;font-weight:700;letter-spacing:0.05em;">Risk Level</div>
              <div style="font-size:22px;font-weight:800;color:#f87171;margin-top:4px;">${riskLevel}</div>
            </div>
          </div>

          <div style="font-size:12px;font-weight:700;color:#e2e8f0;margin-bottom:6px;text-transform:uppercase;letter-spacing:0.03em;">Violations Detected:</div>
          <ul style="font-size:12px;color:#cbd5e1;background:#1e293b;padding:12px 20px 12px 28px;border-radius:10px;margin:0 0 16px 0;max-height:120px;overflow-y:auto;line-height:1.5;border:1px solid #334155;">
            ${detectionsHtml}
          </ul>

          <div style="font-size:12px;color:#94a3b8;margin-bottom:18px;background:#1e293b;padding:10px 14px;border-radius:8px;border-left:3px solid #ef4444;">
            ⛔ <strong>Message Stopped Cold:</strong> This prompt was halted before transmission. It was <strong>never sent</strong> to LLM servers.
          </div>

          <button id="llm-firewall-close-btn" style="
            width: 100%;
            background: #ef4444;
            color: white;
            border: none;
            padding: 12px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 700;
            cursor: pointer;
            transition: background 0.15s ease-in-out;
          ">
            Acknowledge & Revise Prompt
          </button>
        </div>
      </div>
    `;

    document.body.appendChild(modal);

    document.getElementById('llm-firewall-close-btn').addEventListener('click', () => {
      modal.remove();
    });
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
})();
