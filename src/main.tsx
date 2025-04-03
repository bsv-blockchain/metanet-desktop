import React from 'react'
import { createRoot } from 'react-dom/client'
import { UserInterface } from './UserInterface'

import { listen, emit } from '@tauri-apps/api/event'
import { invoke } from '@tauri-apps/api/core'
import { WalletContextProvider } from './WalletContext';

// 1. Our Tauri commands exposed as async calls:
async function isFocused(): Promise<boolean> {
  return invoke<boolean>('is_focused')
}

async function requestFocus(): Promise<void> {
  return invoke<void>('request_focus')
}

async function relinquishFocus(): Promise<void> {
  return invoke<void>('relinquish_focus')
}

// 2. Create the root and render:
const rootElement = document.getElementById('root')
const root = createRoot(rootElement!)



root.render(
  <React.StrictMode>
    <WalletContextProvider>
    <UserInterface
      // Pass them as props so they can be injected into the context
      isFocused={isFocused}
      requestFocus={requestFocus}
      relinquishFocus={relinquishFocus}

      onWalletReady={walletBridge}
    />
    </WalletContextProvider>
  </React.StrictMode>
)
