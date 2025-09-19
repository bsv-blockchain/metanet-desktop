import './fetchProxy'
import React from 'react'
import { createRoot } from 'react-dom/client'
import { ToastContainer } from 'react-toastify'
import 'react-toastify/dist/ReactToastify.css'
import { UserInterface } from '@bsv/brc100-ui-react-components'
import { onWalletReady } from './onWalletReady'
import ErrorBoundary from './ErrorBoundary'
import { tauriFunctions } from './tauriFunctions'
import packageJson from '../package.json'
import { createTheme, ThemeProvider } from '@mui/material/styles'
import { registerPreLoginRoutes } from './preLoginRoutes'

// Define a theme that includes the custom structure expected by the components
const theme = createTheme({
  // Add any standard theme overrides here
  templates: {
    page_wrap: {
      // This is needed to prevent the error, define specific styles here if required
    }
  }
})

const preLoginUnlistenPromise = registerPreLoginRoutes()

// Create the root and render:
const rootElement = document.getElementById('root')
if (rootElement) {
  const root = createRoot(rootElement)

  root.render(
    <React.StrictMode>
      <ThemeProvider theme={theme}>
        <ErrorBoundary>
          <UserInterface
            onWalletReady={async (wallet) => {
              try {
                const unlisten = await preLoginUnlistenPromise
                if (typeof unlisten === 'function') {
                  unlisten()
                }
              } catch (e) {
                console.warn('Failed to unlisten pre-login routes:', e)
              }
              return onWalletReady(wallet)
            }}
            nativeHandlers={tauriFunctions}
            appVersion={packageJson.version}
            appName="Metanet Desktop"
          />
        </ErrorBoundary>
        <ToastContainer
          position="top-right"
          autoClose={5000}
          hideProgressBar={false}
          newestOnTop
          closeOnClick
          rtl={false}
          pauseOnFocusLoss
          draggable
          pauseOnHover
          theme="light"
        />
      </ThemeProvider>
    </React.StrictMode>
  )
}
