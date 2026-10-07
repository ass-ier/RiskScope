import { useState, type ReactNode } from 'react'
import { apiResponse, apiUrl } from '../lib/api'
import { ErrorNotice } from './UI'

export function DownloadLink({ path, children, className = 'button' }: {
  path: string; children: ReactNode; className?: string
}) {
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<Error | null>(null)
  async function download() {
    setPending(true)
    setError(null)
    try {
      const response = await apiResponse(path)
      const blob = await response.blob()
      const disposition = response.headers.get('Content-Disposition') || ''
      const filename = disposition.match(/filename="([^"]+)"/)?.[1]?.replace(/[/\\\r\n]/g, '_') || 'riskscope-export'
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = filename
      document.body.append(anchor)
      anchor.click()
      anchor.remove()
      window.setTimeout(() => URL.revokeObjectURL(url), 1000)
    } catch (cause) {
      setError(cause instanceof Error ? cause : new Error('Download failed. Please retry.'))
    } finally {
      setPending(false)
    }
  }
  return <span className="download-action"><a href={apiUrl(path)} download className={className}
    aria-disabled={pending} onClick={event => { event.preventDefault(); if (!pending) void download() }}>
    {pending ? 'Preparing download…' : children}
  </a><ErrorNotice error={error} /></span>
}
