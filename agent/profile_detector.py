"""
Whisper ClipGuard - Browser Profile Detector
Detects whether user is on a work or personal browser profile.
Adjusts risk thresholds based on context.
"""

import json
import os
import platform
from pathlib import Path
from typing import Dict, Optional, List
from dataclasses import dataclass
from enum import Enum


class ProfileType(Enum):
    WORK = "work"
    PERSONAL = "personal"
    UNKNOWN = "unknown"


@dataclass
class ProfileInfo:
    """Browser profile metadata - no sensitive data"""
    profile_type: ProfileType
    browser_name: str
    profile_name: str
    managed_by_organization: bool
    work_extensions_detected: List[str]
    confidence: float  # 0.0 to 1.0


class BrowserProfileDetector:
    """
    Detects browser profile type by examining:
    - Managed policies (enterprise enrollment)
    - Installed extensions (work vs personal)
    - Profile path naming patterns
    - OS user account type
    """
    
    # Extensions commonly installed by enterprise
    WORK_EXTENSION_IDS = [
        # Password managers
        'hdokiejnpimakedhajhdlcegeplioahd',  # LastPass
        'bgejafpldaahobhjlgebincnnfcchpab',  # 1Password
        
        # Security
        'cjpalhdlnbpafiamejdnhcphjbkeiagm',  # uBlock Origin (often in work)
        
        # Enterprise tools
        'ghbmnnjooekpmoecnnnilnnbdlolhkhi',  # Google Docs Offline
        
        # VPN/Proxy
        'jplnlifepflhkbkgonidnobkakhmpnmh',  # Palo Alto GlobalProtect
    ]
    
    # Keywords in profile paths that suggest work
    WORK_PATH_KEYWORDS = ['work', 'corp', 'enterprise', 'company', 'business', 'admin']
    PERSONAL_PATH_KEYWORDS = ['personal', 'home', 'default']
    
    def __init__(self):
        self.system = platform.system()
    
    def get_chrome_profiles(self) -> List[Dict]:
        """Get list of Chrome profiles and their metadata"""
        profiles = []
        
        # Determine Chrome user data directory
        if self.system == 'Windows':
            base_path = Path(os.environ.get('LOCALAPPDATA', '')) / 'Google' / 'Chrome' / 'User Data'
        elif self.system == 'Darwin':
            base_path = Path.home() / 'Library' / 'Application Support' / 'Google' / 'Chrome'
        else:  # Linux
            base_path = Path.home() / '.config' / 'google-chrome'
        
        if not base_path.exists():
            return profiles
        
        # Read Local State for profile info
        local_state_path = base_path / 'Local State'
        if local_state_path.exists():
            try:
                with open(local_state_path, 'r', encoding='utf-8') as f:
                    local_state = json.load(f)
                
                profile_info = local_state.get('profile', {}).get('info_cache', {})
                
                for profile_dir, info in profile_info.items():
                    profile_path = base_path / profile_dir
                    
                    profile_data = {
                        'directory': profile_dir,
                        'name': info.get('name', profile_dir),
                        'email': info.get('user_name', ''),
                        'is_managed': self._check_managed_policies(profile_path),
                        'extensions': self._get_extensions(profile_path)
                    }
                    profiles.append(profile_data)
                    
            except (json.JSONDecodeError, KeyError, PermissionError):
                pass
        
        return profiles
    
    def _check_managed_policies(self, profile_path: Path) -> bool:
        """Check if profile has enterprise managed policies"""
        # Check for policies.json (enterprise policy file)
        policies_path = profile_path / 'policies.json'
        if policies_path.exists():
            return True
        
        # Check for Extensions/External Extensions (force-installed by admin)
        external_ext_path = profile_path / 'External Extensions'
        if external_ext_path.exists():
            try:
                return len(list(external_ext_path.glob('*.json'))) > 0
            except PermissionError:
                pass
        
        return False
    
    def _get_extensions(self, profile_path: Path) -> List[str]:
        """Get list of installed extension IDs for a profile"""
        extensions = []
        extensions_path = profile_path / 'Extensions'
        
        if extensions_path.exists():
            try:
                for ext_dir in extensions_path.iterdir():
                    if ext_dir.is_dir():
                        extensions.append(ext_dir.name)
            except PermissionError:
                pass
        
        return extensions
    
    def detect_profile_type(self, profile_name: str, is_managed: bool, 
                           extensions: List[str]) -> ProfileType:
        """Determine if a profile is work or personal"""
        
        # Strong signals for work profile
        if is_managed:
            return ProfileType.WORK
        
        # Check profile name for keywords
        profile_lower = profile_name.lower()
        if any(kw in profile_lower for kw in self.WORK_PATH_KEYWORDS):
            return ProfileType.WORK
        if any(kw in profile_lower for kw in self.PERSONAL_PATH_KEYWORDS):
            return ProfileType.PERSONAL
        
        # Check extensions
        work_ext_count = sum(
            1 for ext in extensions 
            if ext in self.WORK_EXTENSION_IDS
        )
        
        if work_ext_count >= 3:
            return ProfileType.WORK
        elif work_ext_count >= 1 and len(extensions) < 5:
            return ProfileType.WORK
        
        return ProfileType.UNKNOWN
    
    def get_current_profile_info(self, profile_id: Optional[str] = None) -> ProfileInfo:
        """
        Get profile info for active or specified profile.
        Returns metadata only - no personal information.
        """
        profiles = self.get_chrome_profiles()
        
        if not profiles:
            return ProfileInfo(
                profile_type=ProfileType.UNKNOWN,
                browser_name='chrome',
                profile_name='unknown',
                managed_by_organization=False,
                work_extensions_detected=[],
                confidence=0.0
            )
        
        # If no specific profile, use first one (most common case)
        profile = profiles[0]
        
        profile_type = self.detect_profile_type(
            profile['name'],
            profile['is_managed'],
            profile['extensions']
        )
        
        work_extensions = [e for e in profile['extensions'] if e in self.WORK_EXTENSION_IDS]
        
        return ProfileInfo(
            profile_type=profile_type,
            browser_name='chrome',
            profile_name=profile['name'][:50],  # Truncate for privacy
            managed_by_organization=profile['is_managed'],
            work_extensions_detected=work_extensions,
            confidence=0.9 if profile['is_managed'] else 0.6
        )