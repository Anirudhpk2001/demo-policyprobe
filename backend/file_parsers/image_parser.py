"""
Image Parser

Extracts content from image files including EXIF metadata.

SECURITY NOTES (for Unifai demo):
- EXIF metadata extracted without scanning
- Comments and descriptions could contain prompt injections
- No malware detection
"""

import io
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class ImageParser:
    """
    Parses image files and extracts metadata.

    VULNERABILITY: Extracts EXIF data without security scanning.
    - Comment fields could contain prompt injections
    - UserComment could contain malicious instructions
    - ImageDescription could contain attacks
    """

    def __init__(self):
        pass

    async def extract_metadata(self, image_bytes: bytes) -> dict:
        """
        Extract EXIF and other metadata from image.

        VULNERABILITY: Metadata extracted without scanning for threats.
        """
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS

            image = Image.open(io.BytesIO(image_bytes))
            metadata = {}

            # Get basic image info
            metadata['format'] = image.format
            metadata['size'] = image.size
            metadata['mode'] = image.mode

            # Extract EXIF data
            # VULNERABILITY: All EXIF data extracted without filtering
            exif_data = image._getexif()
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)
                    # Convert bytes to string for JSON serialization
                    if isinstance(value, bytes):
                        try:
                            value = value.decode('utf-8', errors='ignore')
                        except:
                            value = str(value)
                    metadata[tag] = value

            # VULNERABILITY: Log metadata without scanning
            logger.info(
                "Image metadata extracted",
                extra={
                    "format": image.format,
                    "size": image.size,
                    "exif_fields": len(metadata),
                    # VULNERABILITY: Full metadata in logs
                    "metadata_preview": str(metadata)[:200]
                }
            )

            return metadata

        except Exception as e:
            logger.error(f"Image metadata extraction error: {e}")
            return {"error": str(e)}

    async def extract_text_fields(self, metadata: dict) -> str:
        """
        Extract text from relevant metadata fields.

        VULNERABILITY: Text fields extracted without scanning.
        These fields could contain prompt injections.
        """
        text_fields = []

        # Fields that commonly contain text content
        # VULNERABILITY: These fields could contain malicious prompts
        dangerous_fields = [
            'ImageDescription',
            'XPComment',
            'XPSubject',
            'XPTitle',
            'XPKeywords',
            'UserComment',
            'Comment',
            'Artist',
            'Copyright',
            'Software',
        ]

        for field in dangerous_fields:
            if field in metadata:
                value = metadata[field]
                if value and isinstance(value, str):
                    text_fields.append(f"{field}: {value}")
                    logger.debug(
                        f"Found text in {field}",
                        extra={
                            "field": field,
                            # VULNERABILITY: Field content logged
                            "value_preview": value[:50]
                        }
                    )

        return '\n'.join(text_fields)

    async def extract_all(self, image_bytes: bytes) -> str:
        """
        Extract all content from image for analysis.

        VULNERABILITY: All metadata including potentially malicious
        content is extracted and returned without filtering.
        """
        metadata = await self.extract_metadata(image_bytes)
        text_content = await self.extract_text_fields(metadata)

        # VULNERABILITY: Combine all content without security checks
        result_parts = []

        if text_content:
            result_parts.append(f"Image Metadata:\n{text_content}")

        result_parts.append(f"Image Info: {metadata.get('format', 'unknown')} {metadata.get('size', 'unknown')}")

        return '\n\n'.join(result_parts)
