'use client'

import { useState, useRef, useEffect } from 'react'
import { v4 as uuidv4 } from 'uuid'
import { MessageList } from './MessageList'
import { FileUpload } from './FileUpload'
import { Send, Paperclip, Loader2 } from 'lucide-react'

export interface Message {
  id: string
  role: 'user' | 'assistant' | 'system'
  content: string
  timestamp: Date
  attachments?: FileAttachment[]
  error?: PolicyError
}

export interface FileAttachment {
  id: string
  name: string
  type: string
  size: number
  content?: string
}

export interface PolicyError {
  type: 'pii' | 'threat' | 'auth' | 'general'
  message: string
  details?: Record<string, unknown>
}

export function ChatInterface() {
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [pendingFiles, setPendingFiles] = useState<File[]>([])
  const [showFileUpload, setShowFileUpload] = useState(false)
  const inputRef = useRef<HTMLTextAreaElement>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (inputRef.current) {
      inputRef.current.focus()
    }
  }, [])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!input.trim() && pendingFiles.length === 0) return

    const attachments: FileAttachment[] = []

    // Process pending files
    for (const file of pendingFiles) {
      const content = await readFileContent(file)
      attachments.push({
        id: uuidv4(),
        name: file.name,
        type: file.type,
        size: file.size,
        content,
      })
    }

    const userMessage: Message = {
      id: uuidv4(),
      role: 'user',
      content: input || `Uploaded ${pendingFiles.length} file(s)`,
      timestamp: new Date(),
      attachments: attachments.length > 0 ? attachments : undefined,
    }

    setMessages(prev => [...prev, userMessage])
    setInput('')
    setPendingFiles([])
    setShowFileUpload(false)
    setIsLoading(true)

    try {
      const response = await fetch('/api/backend/chat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          message: input,
          attachments: attachments,
          conversation_id: uuidv4(),
        }),
      })

      const data = await response.json()

      if (!response.ok) {
        // Handle policy violations returned as errors
        const errorMessage: Message = {
          id: uuidv4(),
          role: 'assistant',
          content: data.detail || 'An error occurred',
          timestamp: new Date(),
          error: data.policy_error ? {
            type: data.policy_error.type,
            message: data.policy_error.message,
            details: data.policy_error.details,
          } : undefined,
        }
        setMessages(prev => [...prev, errorMessage])
      } else {
        const assistantMessage: Message = {
          id: uuidv4(),
          role: 'assistant',
          content: data.response,
          timestamp: new Date(),
          error: data.policy_warning ? {
            type: data.policy_warning.type,
            message: data.policy_warning.message,
            details: data.policy_warning.details,
          } : undefined,
        }
        setMessages(prev => [...prev, assistantMessage])
      }
    } catch (error) {
      const errorMessage: Message = {
        id: uuidv4(),
        role: 'assistant',
        content: 'Failed to connect to the backend. Please ensure the server is running.',
        timestamp: new Date(),
        error: {
          type: 'general',
          message: 'Connection error',
        },
      }
      setMessages(prev => [...prev, errorMessage])
    } finally {
      setIsLoading(false)
    }
  }

  const readFileContent = (file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader()
      reader.onload = () => {
        const result = reader.result as string
        // For binary files, return base64
        if (file.type.startsWith('image/') || file.type === 'application/pdf') {
          resolve(result.split(',')[1]) // Remove data URL prefix
        } else {
          resolve(result)
        }
      }
      reader.onerror = reject

      if (file.type.startsWith('image/') || file.type === 'application/pdf') {
        reader.readAsDataURL(file)
      } else {
        reader.readAsText(file)
      }
    })
  }

  const handleFileSelect = (files: File[]) => {
    setPendingFiles(prev => [...prev, ...files])
  }

  const removePendingFile = (index: number) => {
    setPendingFiles(prev => prev.filter((_, i) => i !== index))
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSubmit(e)
    }
  }

  return (
    <div className="flex flex-col h-screen">
      {/* Header */}
      <header className="flex items-center justify-center py-3 border-b border-chat-border bg-chat-sidebar">
        <h1 className="text-xl font-semibold text-white">PolicyProbe</h1>
      </header>

      {/* Messages Area */}
      <div className="flex-1 overflow-y-auto chat-scrollbar">
        {messages.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-gray-400">
            <div className="text-4xl mb-4">🔍</div>
            <h2 className="text-2xl font-medium text-white mb-2">PolicyProbe</h2>
            <p className="text-center max-w-md">
              Upload documents to analyze or ask questions about policy compliance.
              <br />
              <span className="text-sm text-gray-500 mt-2 block">
                Supports PDF, Word, HTML, and image files
              </span>
            </p>
          </div>
        ) : (
          <MessageList messages={messages} />
        )}
      </div>

      {/* File Upload Modal */}
      {showFileUpload && (
        <div className="border-t border-chat-border bg-chat-input p-4">
          <FileUpload onFilesSelected={handleFileSelect} />
        </div>
      )}

      {/* Pending Files Display */}
      {pendingFiles.length > 0 && (
        <div className="border-t border-chat-border bg-chat-input px-4 py-2">
          <div className="flex flex-wrap gap-2">
            {pendingFiles.map((file, index) => (
              <div
                key={index}
                className="flex items-center gap-2 bg-chat-hover rounded-lg px-3 py-1.5 text-sm"
              >
                <span className="text-gray-300">{file.name}</span>
                <button
                  onClick={() => removePendingFile(index)}
                  className="text-gray-500 hover:text-red-400"
                >
                  ×
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Input Area */}
      <div className="border-t border-chat-border bg-chat-bg p-4">
        <form onSubmit={handleSubmit} className="max-w-3xl mx-auto">
          <div className="relative flex items-end bg-chat-input rounded-xl border border-chat-border">
            {/* File Upload Button */}
            <button
              type="button"
              onClick={() => setShowFileUpload(!showFileUpload)}
              className="p-3 text-gray-400 hover:text-white transition-colors"
            >
              <Paperclip className="w-5 h-5" />
            </button>

            {/* Hidden file input */}
            <input
              ref={fileInputRef}
              type="file"
              multiple
              accept=".pdf,.doc,.docx,.html,.htm,.txt,.json,.jpg,.jpeg,.png"
              className="hidden"
              onChange={(e) => {
                if (e.target.files) {
                  handleFileSelect(Array.from(e.target.files))
                }
              }}
            />

            {/* Text Input */}
            <textarea
              ref={inputRef}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Message PolicyProbe..."
              className="flex-1 bg-transparent text-white placeholder-gray-500 resize-none py-3 pr-12 focus:outline-none max-h-48"
              rows={1}
              disabled={isLoading}
            />

            {/* Send Button */}
            <button
              type="submit"
              disabled={isLoading || (!input.trim() && pendingFiles.length === 0)}
              className="absolute right-2 bottom-2 p-2 text-gray-400 hover:text-white disabled:opacity-50 disabled:hover:text-gray-400 transition-colors"
            >
              {isLoading ? (
                <Loader2 className="w-5 h-5 animate-spin" />
              ) : (
                <Send className="w-5 h-5" />
              )}
            </button>
          </div>
          <p className="text-xs text-center text-gray-500 mt-2">
            PolicyProbe demonstrates AI policy evaluation and remediation
          </p>
        </form>
      </div>
    </div>
  )
}
