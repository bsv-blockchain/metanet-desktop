import { listen, emit, UnlistenFn } from '@tauri-apps/api/event'
import { invoke } from '@tauri-apps/api/core'

export async function registerPreLoginRoutesOnce(): Promise<UnlistenFn | (() => void)> {
  let alreadyDone = false
  try {
    alreadyDone = await invoke<boolean>('is_prelogin_done')
  } catch (e) {
    console.warn('is_prelogin_done not available; assuming not done yet', e)
  }

  if (alreadyDone) {
    return () => {}
  }

  const unlisten = await listen('http-request', async (event) => {
    try {
      const req = JSON.parse(event.payload as string)

      // Only handle the once-per-install route
      if (req.path !== '/getVersion') {
        return
      }

      let headersObj: Record<string, string> = {}
      if (Array.isArray(req.headers)) {
        headersObj = Object.fromEntries(
          (req.headers as [string, string][]) .map(([k, v]) => [String(k).toLowerCase(), String(v)])
        )
      } else if (req.headers && typeof req.headers === 'object') {
        // Already an object, but ensure lowercase keys
        headersObj = Object.fromEntries(
          Object.entries(req.headers as Record<string, string>).map(([k, v]) => [k.toLowerCase(), String(v)])
        )
      }

      const rawOrigin = headersObj['origin']
      const rawOriginator = headersObj['originator']
      let manifestUrl: string | null = null
      try {
        if (rawOrigin) {
          const u = new URL(rawOrigin)
          manifestUrl = `https://${u.host}/manifest.json`
        } else if (rawOriginator) {
          const candidate = rawOriginator.includes('://') ? rawOriginator : `http://${rawOriginator}`
          const u = new URL(candidate)
          manifestUrl = `https://${u.host}/manifest.json`
        }
      } catch (e) {
        console.warn('Failed to parse origin header for manifest URL:', e)
      }

      if (manifestUrl) {
        try {
          const resp = await invoke<{ status: number; headers: Array<[string, string]>; body: string }>(
            'proxy_fetch_manifest',
            { url: manifestUrl }
          )
          if (resp && resp.status >= 200 && resp.status < 300 && resp.body) {
            try {
              const manifest = JSON.parse(resp.body)
              if (manifest && typeof manifest === 'object' && manifest) {
                try {
                  sessionStorage.setItem('appinfo', JSON.stringify(manifest))

                  console.log('manifestUrl', manifestUrl)
                  console.log('manifest', manifest)

                } catch (e) {
                  console.warn('Failed to write to sessionStorage:', e)
                }
              }
            } catch (e) {
              console.warn('Failed to parse manifest.json body:', e)
            }
          } else {
            console.warn('proxy_fetch_manifest returned non-2xx or empty body', resp && resp.status)
          }
        } catch (e) {
          console.warn('proxy_fetch_manifest failed:', e)
        }
      } else {
        console.warn('No Origin/Originator header; cannot derive manifest URL')
      }

      emit('ts-response', {
        request_id: req.request_id,
        status: 204,
      })

      // Mark as done and unlisten immediately
      try {
        await invoke<void>('mark_prelogin_done')
      } catch (e) {
        console.warn('mark_prelogin_done failed:', e)
      }

      // Ensure we stop listening after first successful call
      try { unlisten() } catch {}
    } catch (e) {
      console.error('Error in once-only pre-login handler:', e)
    }
  })

  return unlisten
}

export async function registerPreLoginRoutes(): Promise<UnlistenFn | (() => void)> {
  return registerPreLoginRoutesOnce()
}
