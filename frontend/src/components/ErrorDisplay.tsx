'use client'

import { PolicyError } from './ChatInterface'
import { AlertTriangle, Shield, Eye, Lock, AlertCircle } from 'lucide-react'

interface ErrorDisplayProps {
  error: PolicyError
}

export function ErrorDisplay({ error }: ErrorDisplayProps) {
  const getErrorConfig = (type: PolicyError['type']) => {
    switch (type) {
      case 'pii':
        return {
          icon: Eye,
          title: 'PII Detected',
          bgColor: 'bg-red-900/20',
          borderColor: 'border-red-500',
          iconColor: 'text-red-400',
          titleColor: 'text-red-400',
        }
      case 'threat':
        return {
          icon: AlertTriangle,
          title: 'Security Threat Detected',
          bgColor: 'bg-orange-900/20',
          borderColor: 'border-orange-500',
          iconColor: 'text-orange-400',
          titleColor: 'text-orange-400',
        }
      case 'auth':
        return {
          icon: Lock,
          title: 'Authorization Error',
          bgColor: 'bg-yellow-900/20',
          borderColor: 'border-yellow-500',
          iconColor: 'text-yellow-400',
          titleColor: 'text-yellow-400',
        }
      default:
        return {
          icon: AlertCircle,
          title: 'Error',
          bgColor: 'bg-gray-900/20',
          borderColor: 'border-gray-500',
          iconColor: 'text-gray-400',
          titleColor: 'text-gray-400',
        }
    }
  }

  const config = getErrorConfig(error.type)
  const Icon = config.icon

  return (
    <div
      className={`${config.bgColor} border-l-4 ${config.borderColor} rounded-r-lg p-4`}
    >
      <div className="flex items-start gap-3">
        <div className={`flex-shrink-0 ${config.iconColor}`}>
          <Shield className="w-5 h-5" />
        </div>
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-1">
            <Icon className={`w-4 h-4 ${config.iconColor}`} />
            <h4 className={`font-medium ${config.titleColor}`}>
              {config.title}
            </h4>
          </div>
          <p className="text-gray-300 text-sm">{error.message}</p>

          {error.details && Object.keys(error.details).length > 0 && (
            <div className="mt-3 text-xs">
              <details className="cursor-pointer">
                <summary className="text-gray-400 hover:text-gray-300">
                  View Details
                </summary>
                <pre className="mt-2 bg-black/30 rounded p-2 overflow-x-auto text-gray-400">
                  {JSON.stringify(error.details, null, 2)}
                </pre>
              </details>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
