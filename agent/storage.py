"""
Whisper ClipGuard - Local Storage Engine
SQLite-based storage for stats, allowlists, and settings.
Zero cloud. Zero telemetry. All data stays on device.
"""

import sqlite3
import json
import os
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class WhisperEvent:
    """A single whisper event - stored for statistics"""
    id: Optional[int] = None
    timestamp: str = ""
    destination: str = ""
    pattern_detected: str = ""
    confidence: str = ""
    user_action: str = ""  # 'proceeded' or 'cancelled'
    profile_type: str = ""


@dataclass
class AllowlistedDestination:
    """Trusted destination where whispers are suppressed"""
    id: Optional[int] = None
    domain: str = ""
    added_at: str = ""
    reason: str = ""


class LocalStorage:
    """Local SQLite storage - never touches network"""
    
    DB_PATH = Path.home() / '.whisper-clipguard' / 'storage.db'
    
    def __init__(self):
        self._ensure_db_directory()
        self.conn = sqlite3.connect(str(self.DB_PATH))
        self.conn.row_factory = sqlite3.Row
        self._create_tables()
    
    def _ensure_db_directory(self):
        """Create storage directory if needed"""
        self.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        # Set restrictive permissions
        os.chmod(self.DB_PATH.parent, 0o700)
    
    def _create_tables(self):
        """Initialize database schema"""
        cursor = self.conn.cursor()
        
        cursor.executescript('''
            CREATE TABLE IF NOT EXISTS whisper_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                destination TEXT NOT NULL,
                pattern_detected TEXT NOT NULL,
                confidence TEXT NOT NULL,
                user_action TEXT NOT NULL,
                profile_type TEXT DEFAULT 'unknown'
            );
            
            CREATE TABLE IF NOT EXISTS allowlist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                added_at TEXT NOT NULL,
                reason TEXT DEFAULT ''
            );
            
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            
            CREATE TABLE IF NOT EXISTS monthly_stats (
                month TEXT PRIMARY KEY,  -- Format: YYYY-MM
                total_whispers INTEGER DEFAULT 0,
                        proceeded_count INTEGER DEFAULT 0,
                        cancelled_count INTEGER DEFAULT 0,
                        critical_patterns_detected INTEGER DEFAULT 0
            );
            
            CREATE INDEX IF NOT EXISTS idx_events_timestamp 
                ON whisper_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_destination 
                ON whisper_events(destination);
        ''')
        
        self.conn.commit()
    
    # ─── Event Logging ─────────────────────────
    
    def log_whisper_event(self, destination: str, pattern: str, 
                         confidence: str, action: str, profile: str = "unknown"):
        """Record a whisper interaction - NO sensitive data stored"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO whisper_events 
            (timestamp, destination, pattern_detected, confidence, user_action, profile_type)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            destination,
            pattern,
            confidence,
            action,
            profile
        ))
        self.conn.commit()
        self._update_monthly_stats(pattern, confidence, action)
    
    def _update_monthly_stats(self, pattern: str, confidence: str, action: str):
        """Aggregate monthly statistics"""
        month_key = datetime.now().strftime('%Y-%m')
        cursor = self.conn.cursor()
        
        cursor.execute('''
            INSERT INTO monthly_stats (month, total_whispers, proceeded_count, cancelled_count, critical_patterns_detected)
            VALUES (?, 1, ?, ?, ?)
            ON CONFLICT(month) DO UPDATE SET
                total_whispers = total_whispers + 1,
                proceeded_count = proceeded_count + ?,
                cancelled_count = cancelled_count + ?,
                critical_patterns_detected = critical_patterns_detected + ?
        ''', (
            month_key,
            1 if action == 'proceeded' else 0,
            1 if action == 'cancelled' else 0,
            1 if confidence == 'critical' else 0,
            1 if action == 'proceeded' else 0,
            1 if action == 'cancelled' else 0,
            1 if confidence == 'critical' else 0
        ))
        
        self.conn.commit()
    
    # ─── Statistics & Dashboard ─────────────────
    
    def get_recent_stats(self, days: int = 30) -> Dict:
        """Get statistics for dashboard display"""
        cursor = self.conn.cursor()
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        
        # Total whispers
        cursor.execute('''
            SELECT COUNT(*) FROM whisper_events 
            WHERE timestamp >= ?
        ''', (cutoff,))
        total = cursor.fetchone()[0]
        
        # Proceeded vs cancelled
        cursor.execute('''
            SELECT user_action, COUNT(*) 
            FROM whisper_events 
            WHERE timestamp >= ?
            GROUP BY user_action
        ''', (cutoff,))
        actions = {row[0]: row[1] for row in cursor.fetchall()}
        
        # Top destinations
        cursor.execute('''
            SELECT destination, COUNT(*) as count 
            FROM whisper_events 
            WHERE timestamp >= ?
            GROUP BY destination 
            ORDER BY count DESC 
            LIMIT 5
        ''', (cutoff,))
        top_destinations = [{'domain': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        # Top patterns detected
        cursor.execute('''
            SELECT pattern_detected, COUNT(*) as count 
            FROM whisper_events 
            WHERE timestamp >= ?
            GROUP BY pattern_detected 
            ORDER BY count DESC 
            LIMIT 5
        ''', (cutoff,))
        top_patterns = [{'pattern': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        # Monthly trend
        cursor.execute('''
            SELECT month, total_whispers, proceeded_count, cancelled_count
            FROM monthly_stats
            ORDER BY month DESC
            LIMIT 6
        ''', ())
        monthly_trend = [dict(row) for row in cursor.fetchall()]
        
        # Profile type breakdown
        cursor.execute('''
            SELECT profile_type, COUNT(*)
            FROM whisper_events
            WHERE timestamp >= ?
            GROUP BY profile_type
        ''', (cutoff,))
        profile_stats = {row[0]: row[1] for row in cursor.fetchall()}
        
        return {
            'period_days': days,
            'total_whispers': total,
            'proceeded': actions.get('proceeded', 0),
            'cancelled': actions.get('cancelled', 0),
            'cancelled_percentage': round(
                (actions.get('cancelled', 0) / total * 100) if total > 0 else 0, 1
            ),
            'top_destinations': top_destinations,
            'top_patterns': top_patterns,
            'monthly_trend': monthly_trend,
            'profile_breakdown': profile_stats,
            'protection_score': self._calculate_protection_score(actions, total)
        }
    
    def _calculate_protection_score(self, actions: Dict, total: int) -> int:
        """Calculate a fun 'protection score' for gamification"""
        if total == 0:
            return 100
        cancelled = actions.get('cancelled', 0)
        return min(100, int((cancelled / total) * 100))
    
    # ─── Allowlist Management ─────────────────
    
    def add_to_allowlist(self, domain: str, reason: str = "") -> bool:
        """Add a destination to the allowlist"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT OR IGNORE INTO allowlist (domain, added_at, reason)
                VALUES (?, ?, ?)
            ''', (domain.lower().strip(), datetime.now().isoformat(), reason))
            self.conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error:
            return False
    
    def remove_from_allowlist(self, domain: str) -> bool:
        """Remove a destination from the allowlist"""
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM allowlist WHERE domain = ?', (domain.lower().strip(),))
        self.conn.commit()
        return cursor.rowcount > 0
    
    def is_allowlisted(self, domain: str) -> bool:
        """Check if a domain is allowlisted"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT 1 FROM allowlist WHERE domain = ?', (domain.lower().strip(),))
        return cursor.fetchone() is not None
    
    def get_allowlist(self) -> List[Dict]:
        """Get full allowlist"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT domain, added_at, reason FROM allowlist ORDER BY added_at DESC')
        return [dict(row) for row in cursor.fetchall()]
    
    # ─── Settings ─────────────────────────────
    
    def get_setting(self, key: str, default: str = "") -> str:
        """Get a setting value"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
        row = cursor.fetchone()
        return row[0] if row else default
    
    def set_setting(self, key: str, value: str):
        """Set a setting value"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO settings (key, value)
            VALUES (?, ?)
        ''', (key, value))
        self.conn.commit()
    
    def close(self):
        """Close database connection"""
        self.conn.close()