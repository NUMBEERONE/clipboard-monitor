/**
 * Whisper ClipGuard - Content Script
 * Intercepts paste events, checks with local agent, shows whisper UI.
 * NEVER reads clipboard directly. No clipboardRead permission needed.
 */

const AGENT_URL = 'http://127.0.0.1:9123';

// ─── State ───────────────────────────────
let whisperActive = false;
let currentOverlay = null;
let agentReachable = true;

// ─── Agent Communication ─────────────────

async function checkAgentHealth() {
    try {
        const response = await fetch(`${AGENT_URL}/health`, {
            method: 'GET',
            signal: AbortSignal.timeout(1000)
        });
        agentReachable = response.ok;
        return agentReachable;
    } catch {
        agentReachable = false;
        return false;
    }
}

async function checkPasteRisk(destination) {
    try {
        const response = await fetch(`${AGENT_URL}/check-risk`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                destination: destination,
                timestamp: Date.now()
            }),
            signal: AbortSignal.timeout(2000)
        });
        
        if (!response.ok) return { risk: false };
        return await response.json();
    } catch {
        return { risk: false };
    }
}

async function logWhisperEvent(destination, pattern, confidence, action, profile) {
    try {
        await fetch(`${AGENT_URL}/log-event`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                destination,
                pattern,
                confidence,
                action,
                profile
            }),
            signal: AbortSignal.timeout(1000)
        });
    } catch {
        // Fail silently - logging is non-critical
    }
}

// ─── Whisper UI ──────────────────────────

function createWhisperOverlay(riskData, destination) {
    // Remove existing overlay
    if (currentOverlay) {
        currentOverlay.remove();
    }
    
    const findingsList = riskData.findings || [];
    const primaryFinding = findingsList[0] || {};
    const hasMultiple = findingsList.length > 1;
    
    const overlay = document.createElement('div');
    overlay.id = 'whisper-clipguard-overlay';
    overlay.style.cssText = `
        position: fixed;
        bottom: 24px;
        right: 24px;
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-left: 4px solid ${riskData.risk_score > 0.7 ? '#ef4444' : '#f59e0b'};
        border-radius: 12px;
        padding: 20px 24px;
        z-index: 2147483647;
        box-shadow: 0 20px 60px rgba(0,0,0,0.15), 0 0 0 1px rgba(0,0,0,0.05);
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        max-width: 400px;
        min-width: 320px;
        animation: whisperSlideIn 0.25s cubic-bezier(0.16, 1, 0.3, 1);
        backdrop-filter: blur(10px);
    `;
    
    // Add animation keyframes
    if (!document.getElementById('whisper-animations')) {
        const style = document.createElement('style');
        style.id = 'whisper-animations';
        style.textContent = `
            @keyframes whisperSlideIn {
                from { opacity: 0; transform: translateY(20px) scale(0.95); }
                to { opacity: 1; transform: translateY(0) scale(1); }
            }
            @keyframes whisperPulse {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.6; }
            }
        `;
        document.head.appendChild(style);
    }
    
    const confidenceColor = {
        'critical': '#dc2626',
        'high': '#ea580c',
        'medium': '#ca8a04',
        'low': '#2563eb'
    };
    
    const confidenceBadge = riskData.confidence || 'medium';
    const badgeColor = confidenceColor[confidenceBadge] || '#64748b';
    
    overlay.innerHTML = `
        <div style="display: flex; align-items: flex-start; gap: 14px;">
            <div style="
                flex-shrink: 0;
                width: 44px;
                height: 44px;
                background: ${riskData.risk_score > 0.7 ? '#fef2f2' : '#fffbeb'};
                border-radius: 12px;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 22px;
            ">
                ${riskData.risk_score > 0.7 ? '🔴' : '🟡'}
            </div>
            
            <div style="flex: 1; min-width: 0;">
                <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
                    <span style="font-weight: 600; font-size: 15px; color: #1e293b;">
                        ${riskData.risk_score > 0.7 ? 'Sensitive Data Detected' : 'Are You Sure?'}
                    </span>
                    <span style="
                        font-size: 10px;
                        font-weight: 600;
                        text-transform: uppercase;
                        letter-spacing: 0.5px;
                        background: ${badgeColor}15;
                        color: ${badgeColor};
                        padding: 2px 8px;
                        border-radius: 100px;
                    ">${confidenceBadge}</span>
                </div>
                
                <p style="margin: 4px 0 0; font-size: 13px; color: #64748b; line-height: 1.5;">
                    Pasting <strong style="color: #334155;">${primaryFinding.display || riskData.pattern_type}</strong> 
                    into <strong style="color: #334155;">${destination}</strong>
                    ${hasMultiple ? `<br><span style="font-size: 11px; color: #94a3b8;">+ ${findingsList.length - 1} more pattern(s) detected</span>` : ''}
                </p>
                
                ${riskData.has_image_data ? `
                <div style="
                    margin-top: 8px;
                    padding: 6px 10px;
                    background: #f0f9ff;
                    border-radius: 6px;
                    font-size: 11px;
                    color: #0369a1;
                    display: flex;
                    align-items: center;
                    gap: 6px;
                ">
                    🖼️ Screenshot detected — may contain visible sensitive data
                </div>` : ''}
                
                ${findingsList.length > 1 ? `
                <details style="margin-top: 8px;">
                    <summary style="
                        font-size: 11px;
                        color: #64748b;
                        cursor: pointer;
                        user-select: none;
                    ">View all detections (${findingsList.length})</summary>
                    <div style="margin-top: 6px; font-size: 11px; color: #475569;">
                        ${findingsList.map(f => `
                            <div style="padding: 3px 0; display: flex; justify-content: space-between;">
                                <span>• ${f.display}</span>
                                <span style="color: #94a3b8;">${f.confidence} (${f.count}x)</span>
                            </div>
                        `).join('')}
                    </div>
                </details>` : ''}
            </div>
        </div>
        
        <div style="
            margin-top: 16px;
            display: flex;
            gap: 10px;
            justify-content: flex-end;
        ">
            <button id="whisper-allowlist-btn" style="
                background: transparent;
                border: 1px solid #e2e8f0;
                color: #64748b;
                padding: 8px 14px;
                border-radius: 8px;
                cursor: pointer;
                font-size: 12px;
                font-weight: 500;
                transition: all 0.15s;
            " onmouseover="this.style.background='#f8fafc'" onmouseout="this.style.background='transparent'">
                Always allow ${destination}
            </button>
            
            <button id="whisper-proceed-btn" style="
                background: #ef4444;
                border: none;
                color: white;
                padding: 8px 18px;
                border-radius: 8px;
                cursor: pointer;
                font-size: 13px;
                font-weight: 600;
                transition: all 0.15s;
            " onmouseover="this.style.background='#dc2626'" onmouseout="this.style.background='#ef4444'">
                Paste Anyway
            </button>
            
            <button id="whisper-cancel-btn" style="
                background: #f1f5f9;
                border: none;
                color: #475569;
                padding: 8px 18px;
                border-radius: 8px;
                cursor: pointer;
                font-size: 13px;
                font-weight: 600;
                transition: all 0.15s;
            " onmouseover="this.style.background='#e2e8f0'" onmouseout="this.style.background='#f1f5f9'">
                Cancel
            </button>
        </div>
    `;
    
    return overlay;
}

// ─── Paste Interception ──────────────────

document.addEventListener('paste', async (event) => {
    // Only intercept if agent is reachable
    if (!agentReachable) return;
    
    const target = event.target;
    const isEditable = target.isContentEditable ||
        target.tagName === 'INPUT' ||
        target.tagName === 'TEXTAREA' ||
        target.tagName === 'SELECT';
    
    if (!isEditable) return;
    
    const destination = window.location.hostname;
    
    // Check risk with agent
    const riskData = await checkPasteRisk(destination);
    
    if (!riskData.risk) return;
    
    // Block the paste
    event.preventDefault();
    event.stopPropagation();
    
    // Show whisper UI
    const overlay = createWhisperOverlay(riskData, destination);
    document.body.appendChild(overlay);
    currentOverlay = overlay;
    whisperActive = true;
    
    // Handle button clicks
    const proceedBtn = overlay.querySelector('#whisper-proceed-btn');
    const cancelBtn = overlay.querySelector('#whisper-cancel-btn');
    const allowlistBtn = overlay.querySelector('#whisper-allowlist-btn');
    
    const cleanup = async (action) => {
        overlay.remove();
        currentOverlay = null;
        whisperActive = false;
        
        // Log event
        await logWhisperEvent(
            destination,
            riskData.pattern_type,
            riskData.confidence,
            action,
            riskData.profile_type || 'unknown'
        );
    };
    
    proceedBtn.addEventListener('click', async () => {
        await cleanup('proceeded');
        
        // Re-trigger paste without interception
        const newPaste = new ClipboardEvent('paste', {
            bubbles: true,
            cancelable: true,
            clipboardData: event.clipboardData
        });
        target.dispatchEvent(newPaste);
    });
    
    cancelBtn.addEventListener('click', async () => {
        await cleanup('cancelled');
    });
    
    allowlistBtn.addEventListener('click', async () => {
        try {
            await fetch(`${AGENT_URL}/allowlist`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    domain: destination,
                    reason: 'User allowed from whisper dialog'
                })
            });
        } catch {}
        
        await cleanup('proceeded');
        
        // Proceed with paste
        const newPaste = new ClipboardEvent('paste', {
            bubbles: true,
            cancelable: true,
            clipboardData: event.clipboardData
        });
        target.dispatchEvent(newPaste);
    });
    
    // Keyboard shortcuts
    const keyHandler = (e) => {
        if (!whisperActive) return;
        if (e.key === 'Escape') {
            cancelBtn.click();
            document.removeEventListener('keydown', keyHandler);
        } else if (e.key === 'Enter' && !e.shiftKey) {
            proceedBtn.click();
            document.removeEventListener('keydown', keyHandler);
        }
    };
    document.addEventListener('keydown', keyHandler);
    
}, { capture: true });  // Capture phase to intercept before other handlers

// ─── Initialize ──────────────────────────
checkAgentHealth();

// Periodic health check
setInterval(checkAgentHealth, 30000);

// Notify agent of page context
(async () => {
    try {
        await fetch(`${AGENT_URL}/check-risk`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                destination: window.location.hostname,
                timestamp: Date.now(),
                context_only: true
            }),
            signal: AbortSignal.timeout(1000)
        });
    } catch {}
})();