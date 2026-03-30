"""
PolicyProbe Backend - FastAPI Application

This is the main entry point for the PolicyProbe demo application.
The application demonstrates various security policy violations that
can be detected and remediated by Unifai.
"""

import os
from pathlib import Path

# Load environment variables from .env file
from dotenv import load_dotenv
env_path = Path(__file__).parent.parent / '.env'
load_dotenv(env_path)

import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from agents.orchestrator import AgentOrchestrator
from agents.file_processor import FileProcessorAgent

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    logger.info("PolicyProbe backend starting up...")
    yield
    logger.info("PolicyProbe backend shutting down...")


app = FastAPI(
    title="PolicyProbe",
    description="AI-powered policy evaluation and remediation demo",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5001", "http://127.0.0.1:5001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize agents
orchestrator = AgentOrchestrator()
file_processor = FileProcessorAgent()


class FileAttachment(BaseModel):
    id: str
    name: str
    type: str
    size: int
    content: Optional[str] = None


class ChatRequest(BaseModel):
    message: str
    attachments: Optional[list[FileAttachment]] = None
    conversation_id: Optional[str] = None


class PolicyError(BaseModel):
    type: str
    message: str
    details: Optional[dict] = None


class ChatResponse(BaseModel):
    response: str
    conversation_id: Optional[str] = None
    policy_warning: Optional[PolicyError] = None


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "policyprobe"}


@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """
    Main chat endpoint that processes user messages and file uploads.

    This endpoint:
    1. Receives user messages and optional file attachments
    2. Processes files through the FileProcessorAgent
    3. Routes the request through the AgentOrchestrator
    4. Returns the AI response

    SECURITY NOTES (for Unifai demo):
    - File content is not scanned for PII before processing
    - Hidden content in files is not detected
    - Agent calls are not authenticated
    """
    try:
        # Process any attached files
        file_contents = []
        if request.attachments:
            for attachment in request.attachments:
                logger.info(
                    "Processing attachment",
                    extra={
                        "file_name": attachment.name,
                        "file_type": attachment.type,
                        "file_size": attachment.size,
                        # VULNERABILITY: Logging full request context
                        # This could include sensitive data from the file
                        "request_context": {
                            "message": request.message,
                            "attachment_content_preview": attachment.content[:100] if attachment.content else None
                        }
                    }
                )

                # Process the file content
                processed = await file_processor.process(
                    content=attachment.content,
                    filename=attachment.name,
                    content_type=attachment.type
                )
                file_contents.append({
                    "filename": attachment.name,
                    "extracted_content": processed
                })

        # Build context for the orchestrator
        context = {
            "user_message": request.message,
            "file_contents": file_contents,
            "conversation_id": request.conversation_id,
        }

        # Route through orchestrator
        response = await orchestrator.process(context)

        return ChatResponse(
            response=response.get("response", "I processed your request."),
            conversation_id=request.conversation_id,
            policy_warning=response.get("policy_warning"),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Error processing chat request",
            extra={
                # VULNERABILITY: Error context includes full state
                "error": str(e),
                "request_state": {
                    "message": request.message,
                    "attachments": [a.dict() for a in request.attachments] if request.attachments else None
                }
            }
        )
        raise HTTPException(
            status_code=500,
            detail={
                "detail": "An error occurred processing your request",
                "policy_error": {
                    "type": "general",
                    "message": str(e)
                }
            }
        )


@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """
    Direct file upload endpoint.

    SECURITY NOTES (for Unifai demo):
    - No file content scanning
    - No size limits enforced
    - No malware detection
    """
    content = await file.read()

    # VULNERABILITY: File processed without any security checks
    processed = await file_processor.process(
        content=content.decode('utf-8', errors='ignore'),
        filename=file.filename,
        content_type=file.content_type
    )

    return {
        "filename": file.filename,
        "size": len(content),
        "processed": True,
        "content_preview": processed[:500] if processed else None
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=5500)
