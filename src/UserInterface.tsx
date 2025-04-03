import React, { useState, useEffect, useContext, useCallback } from 'react'
import {
    PermissionEventHandler,
} from '@bsv/wallet-toolbox-client'
import RecoveryKeyHandler from './components/RecoveryKeyHandler'
import PasswordHandler from './components/PasswordHandler'
import SpendingAuthorizationHandler from './components/SpendingAuthorizationHandler'
import ProtocolPermissionHandler from './components/ProtocolPermissionHandler'
import CertificateAccessHandler from './components/CertificateAccessHandler'
import BasketAccessHandler from './components/BasketAccessHandler'
import { AppThemeProvider } from "./components/Theme";
import { ExchangeRateContextProvider } from './components/AmountDisplay/ExchangeRateContextProvider'
import { DEFAULT_SETTINGS, WalletSettings } from '@bsv/wallet-toolbox-client/out/src/WalletSettingsManager'
import { HashRouter as Router, Route, Switch, useHistory } from 'react-router-dom'
import { ToastContainer } from 'react-toastify'
import 'react-toastify/dist/ReactToastify.css'
import { BreakpointProvider } from './utils/useBreakpoints'

import Greeter from './pages/Greeter'
import LostPhone from './pages/Recovery/LostPhone'
import LostPassword from './pages/Recovery/LostPassword'
import Dashboard from './pages/Dashboard'
import Recovery from './pages/Recovery'
import packageJson from '../package.json'

/** Queries for responsive design */
const queries = {
    xs: '(max-width: 500px)',
    sm: '(max-width: 720px)',
    md: '(max-width: 1024px)',
    or: '(orientation: portrait)'
}

// -----
// AuthRedirector: Handles auto-login redirect when snapshot has loaded
// -----
const AuthRedirector: React.FC = () => {
    const history = useHistory();
    const { managers, snapshotLoaded } = useContext(WalletContext);

    useEffect(() => {
        if (
            managers.walletManager &&
            snapshotLoaded &&
            (managers.walletManager as any).authenticated
        ) {
            history.push('/dashboard/apps');
        }
    }, [managers.walletManager, snapshotLoaded, history]);

    return null;
};

// -----
// UserInterface Component Props
// -----
interface UserInterfaceProps {
    onWalletReady: (wallet: any) => void;
    // Focus-handling props:
    isFocused?: () => Promise<boolean>;
    requestFocus?: () => Promise<void>;
    relinquishFocus?: () => Promise<void>;
    adminOriginator?: string;
    appVersion?: string;
    appName?: string;
}

/**
 * The UserInterface component supports both new and returning users.
 * For returning users, if a snapshot exists it is loaded and once authenticated
 * the AuthRedirector (inside Router) sends them to the dashboard.
 * New users see the WalletConfig UI.
 */
export const UserInterface: React.FC<UserInterfaceProps> = ({
    onWalletReady,
    isFocused,
    requestFocus,
    relinquishFocus,
    adminOriginator = 'admin.com',
    appVersion = packageJson.version,
    appName = 'Metanet Desktop'
}) => {
    return (
        <WalletContext.Provider>
            <Router>
                {/* This component handles redirecting once the snapshot is loaded and authentication is valid */}
                <AuthRedirector />
                <ExchangeRateContextProvider>
                    <BreakpointProvider queries={queries}>
                        <AppThemeProvider>
                            <ToastContainer position='top-center' />
                            {/* Setup core handlers */}
                            <PasswordHandler setPasswordRetriever={setPasswordRetriever} />
                            <RecoveryKeyHandler setRecoveryKeySaver={setRecoveryKeySaver} />
                            <SpendingAuthorizationHandler
                                setSpendingAuthorizationCallback={setSpendingAuthorizationCallback}
                            />
                            <BasketAccessHandler
                                setBasketAccessHandler={setBasketAccessCallback}
                            />
                            <ProtocolPermissionHandler
                                setProtocolPermissionCallback={setProtocolPermissionCallback}
                            />
                            <CertificateAccessHandler
                                setCertificateAccessHandler={setCertificateAccessCallback}
                            />
                            {/* When a wallet manager exists, render the app routes */}
                            {managers.walletManager && (
                                <Switch>
                                    <Route exact path='/' component={Greeter} />
                                    <Route exact path='/recovery/lost-phone' component={LostPhone} />
                                    <Route exact path='/recovery/lost-password' component={LostPassword} />
                                    <Route exact path='/recovery' component={Recovery} />
                                    <Route path='/dashboard' component={Dashboard} />
                                </Switch>
                            )}
                        </AppThemeProvider>
                    </BreakpointProvider>
                </ExchangeRateContextProvider>
            </Router>
        </WalletContext.Provider>
    )
}
