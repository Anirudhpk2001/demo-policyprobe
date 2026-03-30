"""
PDF Parser

Extracts text content from PDF files.

SECURITY NOTES (for Unifai demo):
- Extracts ALL text including hidden/white text
- No detection of suspicious formatting
- No malware scanning
"""

import io
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class PDFParser:
    """
    Parses PDF files and extracts text content.

    VULNERABILITY: Extracts hidden text without flagging it.
    - White text on white background is extracted
    - Zero-size font text is extracted
    - Off-page text is extracted
    - Overlapping layers are all extracted
    """

    def __init__(self):
        pass

    async def extract_text(self, pdf_bytes: bytes) -> str:
        """
        Extract all text from a PDF file.

        VULNERABILITY: All text extracted including hidden content.
        No detection or warning for suspicious formatting.
        """
        try:
            from PyPDF2 import PdfReader

            pdf_file = io.BytesIO(pdf_bytes)
            reader = PdfReader(pdf_file)

            text_parts = []
            for page_num, page in enumerate(reader.pages):
                # VULNERABILITY: Extract all text without filtering
                page_text = page.extract_text()
                if page_text:
                    text_parts.append(page_text)

                    logger.debug(
                        f"Extracted text from page {page_num + 1}",
                        extra={
                            "page": page_num + 1,
                            "text_length": len(page_text),
                            # VULNERABILITY: Content in logs
                            "preview": page_text[:100]
                        }
                    )

            full_text = '\n\n'.join(text_parts)

            logger.info(
                "PDF text extraction complete",
                extra={
                    "total_pages": len(reader.pages),
                    "total_text_length": len(full_text)
                }
            )

            return full_text

        except Exception as e:
            logger.error(f"PDF extraction error: {e}")
            return f"Error extracting PDF: {str(e)}"

    async def extract_metadata(self, pdf_bytes: bytes) -> dict:
        """
        Extract PDF metadata.

        VULNERABILITY: Metadata extracted without scanning.
        """
        try:
            from PyPDF2 import PdfReader

            pdf_file = io.BytesIO(pdf_bytes)
            reader = PdfReader(pdf_file)

            metadata = {}
            if reader.metadata:
                for key in reader.metadata:
                    metadata[key] = reader.metadata[key]

            return metadata

        except Exception as e:
            logger.error(f"PDF metadata extraction error: {e}")
            return {}

    async def extract_all(self, pdf_bytes: bytes) -> dict:
        """
        Extract all content from PDF.

        VULNERABILITY: All content extracted without security analysis.
        """
        text = await self.extract_text(pdf_bytes)
        metadata = await self.extract_metadata(pdf_bytes)

        return {
            "text": text,
            "metadata": metadata,
            "warnings": []  # VULNERABILITY: No warnings generated
        }
