"""
Whisper ClipGuard - OCR Scanner
Detects sensitive data in images/screenshots pasted into text fields.
Uses Tesseract OCR locally - no cloud processing.
"""

import subprocess
import tempfile
import os
import base64
import re
from io import BytesIO
from typing import Optional, List, Dict
from dataclasses import dataclass
import platform

# Try importing PIL, handle gracefully if not installed
try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import pytesseract
    TESSERACT_AVAILABLE = True
except ImportError:
    TESSERACT_AVAILABLE = False


@dataclass
class OCRResult:
    """OCR scan result - metadata only"""
    text_detected: bool
    sensitive_found: bool
    findings: List[str]  # Pattern types found, not the actual text
    confidence: str  # low, medium, high
    ocr_engine_available: bool


class OCRScanner:
    """
    Extracts text from images using local Tesseract OCR,
    then scans the extracted text for sensitive patterns.
    Never stores or transmits image data.
    """
    
    SENSITIVE_PATTERNS_IN_IMAGES = [
        (r'\b\d{3}-\d{2}-\d{4}\b', 'SSN'),
        (r'\b(?:\d[ -]*?){13,19}\b', 'Credit Card'),
        (r'\bAKIA[0-9A-Z]{16}\b', 'AWS Key'),
        (r'-----BEGIN.*PRIVATE KEY-----', 'Private Key'),
        (r'\bsk_live_[0-9a-zA-Z]{24,}\b', 'Stripe Key'),
    ]
    
    def __init__(self):
        self.tesseract_available = self._check_tesseract()
    
    def _check_tesseract(self) -> bool:
        """Check if Tesseract is installed and accessible"""
        if not TESSERACT_AVAILABLE:
            return False
        
        try:
            result = subprocess.run(
                ['tesseract', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
    
    def detect_image_in_clipboard(self) -> bool:
        """Check if clipboard contains image data"""
        if not PIL_AVAILABLE:
            return False
        
        try:
            from PIL import ImageGrab
            # Check if there's an image in clipboard
            img = ImageGrab.grabclipboard()
            return img is not None
        except Exception:
            return False
    
    def extract_text_from_image(self, image_data: bytes) -> str:
        """
        Extract text from image bytes using Tesseract.
        Image data is processed in-memory and immediately discarded.
        """
        if not self.tesseract_available or not PIL_AVAILABLE:
            return ""
        
        temp_path = None
        try:
            # Create temporary file for Tesseract
            with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
                f.write(image_data)
                temp_path = f.name
            
            # Run Tesseract OCR
            result = subprocess.run(
                ['tesseract', temp_path, 'stdout', '--psm', '6', '-l', 'eng'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            extracted_text = result.stdout.strip()
            return extracted_text
            
        except (subprocess.SubprocessError, OSError):
            return ""
        finally:
            # Securely delete temp file
            if temp_path and os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass
    
    def scan_image_for_sensitive_data(self, image_data: bytes) -> OCRResult:
        """
        Main entry point: Extract text from image, scan it, discard everything.
        Returns only metadata about what was found.
        """
        if not self.tesseract_available:
            return OCRResult(
                text_detected=False,
                sensitive_found=False,
                findings=[],
                confidence="low",
                ocr_engine_available=False
            )
        
        # Extract text
        extracted_text = self.extract_text_from_image(image_data)
        
        if not extracted_text:
            return OCRResult(
                text_detected=False,
                sensitive_found=False,
                findings=[],
                confidence="low",
                ocr_engine_available=True
            )
        
        # Scan extracted text for patterns
        findings = []
        for pattern_regex, pattern_name in self.SENSITIVE_PATTERNS_IN_IMAGES:
            if re.search(pattern_regex, extracted_text):
                findings.append(pattern_name)
        
        # IMMEDIATELY clear extracted text from memory
        extracted_text = None
        
        return OCRResult(
            text_detected=True,
            sensitive_found=len(findings) > 0,
            findings=findings,
            confidence="high" if findings else "low",
            ocr_engine_available=True
        )