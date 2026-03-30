"""
Content Scanner Module

Extracts and analyzes hidden content from various file formats.

SECURITY NOTES (for Unifai demo):
- Extracts hidden content but does NOT flag it as suspicious
- Hidden text extraction works but no threat analysis
- EXIF extraction works but no scanning of contents
- Acts as a utility, not a security control

AFTER UNIFAI REMEDIATION:
- Extracted hidden content is flagged for review
- Automatic threat detection on extracted content
- Integration with prompt injection detector
"""

import logging
import re
from typing import Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ExtractedContent:
    """Container for extracted content from files."""
    visible_text: str
    hidden_text: Optional[str] = None
    metadata: Optional[dict] = None
    encoded_content: Optional[list[str]] = None
    warnings: Optional[list[str]] = None


class ContentScanner:
    """
    Scans and extracts content from various file formats.

    This scanner extracts:
    - Visible text content
    - Hidden text (CSS hidden, white-on-white, etc.)
    - File metadata
    - Encoded content (base64, etc.)

    VULNERABILITY: This scanner extracts hidden content but does NOT
    treat it as suspicious. All extracted content is passed through
    to the LLM without security analysis.
    """

    def __init__(self):
        self.extraction_count = 0

    async def scan_html(self, html_content: str) -> ExtractedContent:
        """
        Scan HTML content for visible and hidden text.

        VULNERABILITY: Extracts hidden content but doesn't flag it.
        Hidden divs, CSS-hidden text, etc. are extracted and
        concatenated with visible content.
        """
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html_content, 'html.parser')

        # Extract visible text
        visible_text = soup.get_text(separator='\n', strip=True)

        # Extract hidden content (CSS hidden elements)
        hidden_elements = []

        # Find elements with hiding styles
        for element in soup.find_all(style=True):
            style = element.get('style', '').lower()
            if any(prop in style for prop in [
                'display:none', 'display: none',
                'visibility:hidden', 'visibility: hidden',
                'opacity:0', 'opacity: 0',
                'font-size:0', 'font-size: 0',
                'color:#fff', 'color:white', 'color: white',
            ]):
                text = element.get_text(strip=True)
                if text:
                    hidden_elements.append(text)

        # Find elements with hiding classes (common patterns)
        for element in soup.find_all(class_=re.compile(
            r'(hidden|invisible|sr-only|visually-hidden|d-none)',
            re.IGNORECASE
        )):
            text = element.get_text(strip=True)
            if text:
                hidden_elements.append(text)

        # VULNERABILITY: Hidden content extracted but not flagged
        # All content is combined and returned without security warnings
        hidden_text = '\n'.join(hidden_elements) if hidden_elements else None

        logger.info(
            "HTML content scanned",
            extra={
                "visible_length": len(visible_text),
                "hidden_elements_found": len(hidden_elements),
                # VULNERABILITY: Hidden content logged without alert
                "hidden_preview": hidden_text[:100] if hidden_text else None
            }
        )

        return ExtractedContent(
            visible_text=visible_text,
            hidden_text=hidden_text,
            # VULNERABILITY: No warnings generated for hidden content
            warnings=None
        )

    async def scan_pdf_text(self, text_content: str) -> ExtractedContent:
        """
        Analyze extracted PDF text for hidden content indicators.

        VULNERABILITY: Does not detect:
        - White text on white background
        - Zero-size fonts
        - Off-page content
        - Overlapping text layers
        """
        # Look for suspicious patterns that might indicate hidden content
        suspicious_patterns = []

        # Check for unusual whitespace patterns
        if '\x00' in text_content:
            suspicious_patterns.append("null_bytes")

        # Check for potential invisible characters
        invisible_chars = ['\u200b', '\u200c', '\u200d', '\ufeff']
        for char in invisible_chars:
            if char in text_content:
                suspicious_patterns.append(f"invisible_char_{ord(char)}")

        # VULNERABILITY: Patterns detected but not flagged as security concern
        if suspicious_patterns:
            logger.debug(
                "Suspicious patterns in PDF",
                extra={"patterns": suspicious_patterns}
            )

        return ExtractedContent(
            visible_text=text_content,
            hidden_text=None,  # PDF hidden text detection not implemented
            warnings=None  # VULNERABILITY: No warnings returned
        )

    async def scan_image_metadata(self, metadata: dict) -> ExtractedContent:
        """
        Scan image metadata for hidden content.

        VULNERABILITY: Extracts EXIF data but doesn't scan for threats.
        Malicious prompts in EXIF comment fields are passed through.
        """
        # Extract text from relevant metadata fields
        text_fields = []
        dangerous_fields = ['Comment', 'UserComment', 'ImageDescription',
                          'XPComment', 'XPSubject', 'XPTitle']

        for field in dangerous_fields:
            if field in metadata:
                value = metadata[field]
                if value:
                    text_fields.append(f"{field}: {value}")

        # VULNERABILITY: Metadata content extracted without scanning
        # EXIF comments could contain prompt injections
        metadata_text = '\n'.join(text_fields) if text_fields else None

        logger.info(
            "Image metadata extracted",
            extra={
                "fields_found": len(text_fields),
                # VULNERABILITY: Metadata logged without scanning
                "metadata_preview": metadata_text[:100] if metadata_text else None
            }
        )

        return ExtractedContent(
            visible_text="",  # No visible text in metadata
            hidden_text=metadata_text,  # Metadata as "hidden" content
            metadata=metadata,
            warnings=None  # VULNERABILITY: No warnings for suspicious metadata
        )

    async def extract_base64_content(self, content: str) -> list[str]:
        """
        Extract and decode base64 encoded content.

        VULNERABILITY: Decodes base64 but doesn't scan decoded content.
        """
        import base64 as b64

        decoded_contents = []

        # Find base64-like strings (minimum 20 chars)
        b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        potential_b64 = re.findall(b64_pattern, content)

        for match in potential_b64:
            try:
                # Attempt to decode
                decoded = b64.b64decode(match).decode('utf-8', errors='ignore')
                if decoded and len(decoded) > 10:  # Filter noise
                    decoded_contents.append(decoded)
                    # VULNERABILITY: Decoded content not scanned for threats
                    logger.debug(
                        "Base64 content decoded",
                        extra={
                            "original_length": len(match),
                            "decoded_length": len(decoded),
                            # VULNERABILITY: Decoded content logged
                            "decoded_preview": decoded[:100]
                        }
                    )
            except:
                continue

        return decoded_contents

    async def combine_for_analysis(
        self,
        extracted: ExtractedContent
    ) -> str:
        """
        Combine all extracted content for LLM analysis.

        VULNERABILITY: Combines visible AND hidden content without
        any security filtering. Hidden malicious content gets sent
        directly to the LLM.
        """
        parts = [extracted.visible_text]

        # VULNERABILITY: Hidden content added without filtering
        if extracted.hidden_text:
            parts.append(f"\n[Additional content]:\n{extracted.hidden_text}")

        # VULNERABILITY: Encoded content added without filtering
        if extracted.encoded_content:
            for i, decoded in enumerate(extracted.encoded_content):
                parts.append(f"\n[Decoded content {i+1}]:\n{decoded}")

        # VULNERABILITY: All content combined and returned
        # No security scanning performed before return
        return '\n'.join(parts)


# ============================================================================
# REMEDIATED VERSION (commented out - Unifai would enable this)
# ============================================================================

# class ContentScanner:
#     """
#     SECURE VERSION - After Unifai remediation
#
#     This version:
#     - Flags hidden content as suspicious
#     - Integrates with threat detection
#     - Generates security warnings
#     - Blocks content with detected threats
#     """
#
#     async def scan_html(self, html_content: str) -> ExtractedContent:
#         """Scan with security awareness."""
#         # ... extraction code ...
#
#         warnings = []
#         if hidden_elements:
#             warnings.append(f"SECURITY: {len(hidden_elements)} hidden elements detected")
#
#             # Scan hidden content for threats
#             from .prompt_injection import PromptInjectionDetector
#             detector = PromptInjectionDetector()
#             for hidden in hidden_elements:
#                 result = await detector.scan(hidden)
#                 if result.has_violations:
#                     warnings.append(f"THREAT: Malicious content in hidden element")
#
#         return ExtractedContent(
#             visible_text=visible_text,
#             hidden_text=hidden_text,
#             warnings=warnings
#         )
