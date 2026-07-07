#!/usr/bin/env python3
"""
Whisper ClipGuard - Main Agent
Local clipboard monitor + risk assessment server.
Binds to localhost only. Zero network exposure.
"""

import asyncio
import json
import hashlib
import time
import sys
import signal
from datetime import datetime, timedelta
from aiohttp import web
import pyperclip
import platform

from scanner import ClipboardScanner, ScanResult, Confidence
from ocr_scanner import OCRScanner
from profile_detector import BrowserProfileDetector, ProfileType
from storage import LocalStorage


class WhisperAgent:
    """Main agent coordinating all subsystems"""
    
    PORT = 9123
    HOST = '127.0.0.1'  # LOCALHOST ONLY - never exposed
    
    # Risk scoring thresholds by profile type
    RISK_THRESHOLDS = {
        ProfileType.WORK: {
            Confidence.LOW: 0.1,
            Confidence.MEDIUM: 0.4,
            Confidence.HIGH: 0.7,
            Confidence.CRITICAL: 0.9
        },
        ProfileType.PERSONAL: {
            Confidence.LOW: 0.2,
            Confidence.MEDIUM: 0.5,
            Confidence.HIGH: 0.8,
            Confidence.CRITICAL: 0.95
        },
        ProfileType.UNKNOWN: {
            Confidence.LOW: 0.15,
            Confidence.MEDIUM: 0.45,
            Confidence.HIGH: 0.75,
            Confidence.CRITICAL: 0.9
        }
    }
    
    # Destinations that are always high-risk
    HIGH_RISK_DESTINATIONS = [
        'pastebin.com',
        'pastie.org',
        'ghostbin.com',
        'hastebin.com',
        'termbin.com',
        'ix.io',
        '0bin.net',
        'dpaste.org',
        'chat.openai.com',
        'chatgpt.com',
        'claude.ai',
        'bard.google.com',
        'perplexity.ai',
        'translate.google.com',
        'deepl.com',
        'gmail.com',
        'yahoo.com',
        'outlook.com',
        'proton.me',
        'tutanota.com',
        'facebook.com',
        'twitter.com',
        'x.com',
        'linkedin.com',
        'reddit.com',
        'discord.com',
        'telegram.org',
        'whatsapp.com',
        'signal.org',
        'github.com',
        'gitlab.com',
        'bitbucket.org',
        'stackoverflow.com',
        'codepen.io',
        'jsfiddle.net',
        'codesandbox.io',
        'replit.com',
        'docs.google.com',
        'notion.so',
        'slack.com',
        'teams.microsoft.com',
        'zoom.us',
        'meet.google.com',
    ]
    
    def __init__(self):
        self.scanner = ClipboardScanner()
        self.ocr_scanner = OCRScanner()
        self.profile_detector = BrowserProfileDetector()
        self.storage = LocalStorage()
        
        self.last_clipboard_hash = ""
        self.last_scan_result: ScanResult = None
        self.clipboard_risk_valid_until = None
        self.silent_mode = False
        self.silent_mode_until = None
        self.running = True
        
        # Load settings
        self.silent_mode = self.storage.get_setting('silent_mode', 'false') == 'true'
    
    def _get_current_profile_info(self):
        """Get profile info, fail gracefully"""
        try:
            return self.profile_detector.get_current_profile_info()
        except Exception:
            from profile_detector import ProfileInfo
            return ProfileInfo(
                profile_type=ProfileType.UNKNOWN,
                browser_name='unknown',
                profile_name='unknown',
                managed_by_organization=False,
                work_extensions_detected=[],
                confidence=0.0
            )
    
    def scan_current_clipboard(self) -> ScanResult:
        """
        Read clipboard, scan it, immediately destroy contents.
        Returns only metadata.
        """
        try:
            clipboard_text = pyperclip.paste()
        except Exception:
            return ScanResult(risk_detected=False)
        
        if not clipboard_text:
            return ScanResult(risk_detected=False)
        
        # Hash clipboard to detect if it's changed (hash is one-way)
        current_hash = hashlib.sha256(clipboard_text.encode('utf-8', errors='ignore')).hexdigest()
        
        # If clipboard hasn't changed, return cached result
        if (current_hash == self.last_clipboard_hash and 
            self.last_scan_result and
            self.clipboard_risk_valid_until and 
            datetime.now() < self.clipboard_risk_valid_until):
            return self.last_scan_result
        
        # Scan the content
        result = self.scanner.scan_text(clipboard_text)
        
        # Cache the result
        self.last_clipboard_hash = current_hash
        self.last_scan_result = result
        self.clipboard_risk_valid_until = datetime.now() + timedelta(seconds=30)
        
        # Security: Explicitly clear clipboard_text
        clipboard_text = None
        
        return result
    
    def check_image_in_clipboard(self) -> bool:
        """Check if clipboard contains image data"""
        return self.ocr_scanner.detect_image_in_clipboard()
    
    def should_warn(self, scan_result: ScanResult, destination: str, 
                   profile_type: ProfileType) -> dict:
        """
        Decision engine: Should we warn the user?
        Combines: pattern confidence + destination risk + profile context
        """
        # Check silent mode
        if self.silent_mode:
            if self.silent_mode_until and datetime.now() < self.silent_mode_until:
                return {"should_warn": False, "reason": "silent_mode_active"}
            else:
                self.silent_mode = False
                self.storage.set_setting('silent_mode', 'false')
        
        # Check allowlist
        if self.storage.is_allowlisted(destination):
            return {"should_warn": False, "reason": "destination_allowlisted"}
        
        # No risk detected
        if not scan_result.risk_detected:
            return {"should_warn": False, "reason": "no_risk_detected"}
        
        # Calculate base risk score
        highest_confidence = scan_result.overall_confidence
        base_risk = self.RISK_THRESHOLDS[profile_type].get(highest_confidence, 0.5)
        
        # Boost risk for high-risk destinations
        if any(d in destination.lower() for d in self.HIGH_RISK_DESTINATIONS):
            base_risk = min(1.0, base_risk * 1.5)
        
        # Boost for multiple findings
        if len(scan_result.findings) > 1:
            base_risk = min(1.0, base_risk * 1.2)
        
        # Boost for high entropy (unrecognized secrets)
        if scan_result.entropy_score > 4.8:
            base_risk = min(1.0, base_risk * 1.3)
        
        should_warn = base_risk >= 0.3
        
        return {
            "should_warn": should_warn,
            "risk_score": round(base_risk, 2),
            "reason": scan_result.findings[0].display_name if scan_result.findings else "unknown",
            "confidence": highest_confidence.value,
            "multiple_findings": len(scan_result.findings) > 1,
            "all_findings": [
                {
                    "pattern": f.pattern_name,
                    "display": f.display_name,
                    "confidence": f.confidence.value,
                    "count": f.match_count
                }
                for f in scan_result.findings
            ]
        }
    
    # ─── HTTP API Endpoints ─────────────────
    
    async def handle_risk_check(self, request):
        """
        POST /check-risk
        Called by browser extension before paste.
        Body: {destination: string, timestamp: number}
        Response: {risk: bool, ...metadata}
        """
        try:
            body = await request.json()
        except json.JSONDecodeError:
            return web.json_response({"error": "invalid_json"}, status=400)
        
        destination = body.get('destination', '')
        
        # Scan clipboard
        scan_result = self.scan_current_clipboard()
        
        # Check for images in clipboard
        has_image = self.check_image_in_clipboard()
        if has_image:
            scan_result.has_image_data = True
        
        # Get profile context
        profile_info = self._get_current_profile_info()
        
        # Decision
        warning_decision = self.should_warn(
            scan_result, destination, profile_info.profile_type
        )
        
        response = {
            "risk": warning_decision["should_warn"],
            "risk_score": warning_decision.get("risk_score", 0),
            "confidence": warning_decision.get("confidence", "low"),
            "pattern_type": warning_decision.get("reason", "unknown"),
            "multiple_findings": warning_decision.get("multiple_findings", False),
            "findings": warning_decision.get("all_findings", []),
            "profile_type": profile_info.profile_type.value,
            "has_image_data": has_image,
            "silent_mode": self.silent_mode,
            "agent_version": "1.0.0"
        }
        
        return web.json_response(response)
    
    async def handle_log_event(self, request):
        """
        POST /log-event
        Records user action for statistics.
        Body: {destination, pattern, confidence, action, profile}
        """
        try:
            body = await request.json()
        except json.JSONDecodeError:
            return web.json_response({"error": "invalid_json"}, status=400)
        
        self.storage.log_whisper_event(
            destination=body.get('destination', ''),
            pattern=body.get('pattern', ''),
            confidence=body.get('confidence', ''),
            action=body.get('action', 'proceeded'),
            profile=body.get('profile', 'unknown')
        )
        
        return web.json_response({"status": "logged"})
    
    async def handle_allowlist(self, request):
        """
        POST /allowlist - Add destination to allowlist
        DELETE /allowlist - Remove destination from allowlist
        GET /allowlist - List allowlisted destinations
        """
        if request.method == 'POST':
            body = await request.json()
            domain = body.get('domain', '')
            reason = body.get('reason', 'User allowed')
            
            success = self.storage.add_to_allowlist(domain, reason)
            return web.json_response({"success": success, "domain": domain})
        
        elif request.method == 'DELETE':
            domain = request.query.get('domain', '')
            success = self.storage.remove_from_allowlist(domain)
            return web.json_response({"success": success})
        
        else:  # GET
            allowlist = self.storage.get_allowlist()
            return web.json_response({"allowlist": allowlist})
    
    async def handle_silent_mode(self, request):
        """
        POST /silent-mode
        Toggle silent mode.
        Body: {enabled: bool, duration_minutes: int}
        """
        body = await request.json()
        enabled = body.get('enabled', False)
        duration = body.get('duration_minutes', 5)
        
        self.silent_mode = enabled
        self.storage.set_setting('silent_mode', str(enabled).lower())
        
        if enabled:
            self.silent_mode_until = datetime.now() + timedelta(minutes=duration)
        
        return web.json_response({
            "silent_mode": self.silent_mode,
            "until": self.silent_mode_until.isoformat() if self.silent_mode_until else None
        })
    
    async def handle_custom_patterns(self, request):
        """
        POST /custom-patterns - Add pattern
        DELETE /custom-patterns - Remove pattern
        GET /custom-patterns - List patterns
        """
        if request.method == 'POST':
            body = await request.json()
            name = body.get('name', '')
            regex = body.get('regex', '')
            display = body.get('display', name)
            confidence = body.get('confidence', 'high')
            
            success = self.scanner.patterns.add_custom_pattern(name, regex, display, confidence)
            if success:
                self.scanner.save_custom_patterns()
            
            return web.json_response({"success": success})
        
        elif request.method == 'DELETE':
            name = request.query.get('name', '')
            success = self.scanner.patterns.remove_custom_pattern(name)
            if success:
                self.scanner.save_custom_patterns()
            return web.json_response({"success": success})
        
        else:  # GET
            custom = {
                name: {
                    'display': config['display'],
                    'confidence': config['confidence'].value,
                    'is_custom': True
                }
                for name, config in self.scanner.patterns.custom_patterns.items()
            }
            return web.json_response({"custom_patterns": custom})
    
    async def handle_dashboard(self, request):
        """GET /dashboard - Get dashboard statistics"""
        days = int(request.query.get('days', 30))
        stats = self.storage.get_recent_stats(days)
        return web.json_response(stats)
    
    async def handle_health(self, request):
        """GET /health - Health check"""
        return web.json_response({
            "status": "ok",
            "agent_version": "1.0.0",
            "platform": platform.system(),
            "silent_mode": self.silent_mode,
            "uptime_seconds": time.time() - self.start_time
        })
    
    def run(self):
        """Start the agent server"""
        self.start_time = time.time()
        
        app = web.Application()
        
        # Register routes
        app.router.add_post('/check-risk', self.handle_risk_check)
        app.router.add_post('/log-event', self.handle_log_event)
        app.router.add_get('/allowlist', self.handle_allowlist)
        app.router.add_post('/allowlist', self.handle_allowlist)
        app.router.add_delete('/allowlist', self.handle_allowlist)
        app.router.add_post('/silent-mode', self.handle_silent_mode)
        app.router.add_get('/custom-patterns', self.handle_custom_patterns)
        app.router.add_post('/custom-patterns', self.handle_custom_patterns)
        app.router.add_delete('/custom-patterns', self.handle_custom_patterns)
        app.router.add_get('/dashboard', self.handle_dashboard)
        app.router.add_get('/health', self.handle_health)
        
        print(f"""
╔══════════════════════════════════════════╗
║   Whisper ClipGuard Agent v1.0.0        ║
║   Running on 127.0.0.1:{self.PORT}            ║
║   All data stays local. Zero telemetry. ║
╚══════════════════════════════════════════╝
        """)
        
        web.run_app(app, host=self.HOST, port=self.PORT, 
                   print=lambda *args: None)  # Suppress aiohttp logs


if __name__ == '__main__':
    agent = WhisperAgent()
    
    # Graceful shutdown
    def shutdown(sig, frame):
        print("\nShutting down Whisper ClipGuard...")
        agent.storage.close()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    
    agent.run()