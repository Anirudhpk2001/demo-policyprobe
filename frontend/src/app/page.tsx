'use client'

import { ChatInterface } from '@/components/ChatInterface'

export default function Home() {
  return (
    <main className="flex min-h-screen flex-col bg-chat-bg">
      <ChatInterface />
    </main>
  )
}
