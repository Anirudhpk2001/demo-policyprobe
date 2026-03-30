'use client'

import { Message } from './ChatInterface'
import { ErrorDisplay } from './ErrorDisplay'
import { User, Bot, Paperclip } from 'lucide-react'

interface MessageListProps {
  messages: Message[]
}

export function MessageList({ messages }: MessageListProps) {
  return (
    <div className="flex flex-col">
      {messages.map((message) => (
        <div
          key={message.id}
          className={`py-6 ${
            message.role === 'assistant' ? 'bg-chat-hover' : ''
          }`}
        >
          <div className="max-w-3xl mx-auto px-4 flex gap-4">
            {/* Avatar */}
            <div
              className={`flex-shrink-0 w-8 h-8 rounded-sm flex items-center justify-center ${
                message.role === 'user'
                  ? 'bg-purple-600'
                  : 'bg-teal-600'
              }`}
            >
              {message.role === 'user' ? (
                <User className="w-5 h-5 text-white" />
              ) : (
                <Bot className="w-5 h-5 text-white" />
              )}
            </div>

            {/* Content */}
            <div className="flex-1 min-w-0">
              {/* Attachments */}
              {message.attachments && message.attachments.length > 0 && (
                <div className="flex flex-wrap gap-2 mb-3">
                  {message.attachments.map((attachment) => (
                    <div
                      key={attachment.id}
                      className="flex items-center gap-2 bg-chat-input rounded-lg px-3 py-2 text-sm border border-chat-border"
                    >
                      <Paperclip className="w-4 h-4 text-gray-400" />
                      <span className="text-gray-300">{attachment.name}</span>
                      <span className="text-gray-500 text-xs">
                        ({formatFileSize(attachment.size)})
                      </span>
                    </div>
                  ))}
                </div>
              )}

              {/* Message Content or Error */}
              {message.error ? (
                <ErrorDisplay error={message.error} />
              ) : (
                <div className="message-content text-gray-100">
                  {message.content}
                </div>
              )}

              {/* Timestamp */}
              <div className="text-xs text-gray-500 mt-2">
                {formatTime(message.timestamp)}
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function formatTime(date: Date): string {
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}
