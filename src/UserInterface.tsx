import React, { useState, useEffect, createContext, useContext, useMemo } from 'react'
import {
    Wallet,
    WalletPermissionsManager,
    PrivilegedKeyManager,
    WalletStorageManager,
    PermissionEventHandler,
    WalletAuthenticationManager,
    OverlayUMPTokenInteractor,
    WalletSigner,
    Services,
    StorageClient,
    TwilioPhoneInteractor,
    WABClient
} from '@bsv/wallet-toolbox-client'
import {
    KeyDeriver,
    PrivateKey,
    SHIPBroadcaster,
    Utils,
    LookupResolver
} from '@bsv/sdk'
import RecoveryKeyHandler from './components/RecoveryKeyHandler'
import PasswordHandler from './components/PasswordHandler'
import SpendingAuthorizationHandler from './components/SpendingAuthorizationHandler'
import ProtocolPermissionHandler from './components/ProtocolPermissionHandler'
import CertificateAccessHandler from './components/CertificateAccessHandler'
import BasketAccessHandler from './components/BasketAccessHandler'
import { AppThemeProvider } from "./components/Theme";
import { ExchangeRateContextProvider } from './components/AmountDisplay/ExchangeRateContextProvider'
import { DEFAULT_SETTINGS, WalletSettings, WalletSettingsManager } from '@bsv/wallet-toolbox-client/out/src/WalletSettingsManager'
import { HashRouter as Router, Route, Switch, useHistory } from 'react-router-dom'
import { ToastContainer, toast } from 'react-toastify'
import 'react-toastify/dist/ReactToastify.css'
import { BreakpointProvider } from './utils/useBreakpoints'

import Greeter from './pages/Greeter'
import LostPhone from './pages/Recovery/LostPhone'
import LostPassword from './pages/Recovery/LostPassword'
import Welcome from './pages/Welcome'
import Dashboard from './pages/Dashboard'
import Recovery from './pages/Recovery'
import { DEFAULT_WAB_URL, DEFAULT_STORAGE_URL, DEFAULT_CHAIN } from './config'
import packageJson from '../package.json'

// Define a type for the config from WalletConfig component
type WalletConfigType = {
    wabUrl: string;
    selectedAuthMethod: string;
    selectedNetwork: 'main' | 'test';
}

/** Queries for responsive design */
const queries = {
    xs: '(max-width: 500px)',
    sm: '(max-width: 720px)',
    md: '(max-width: 1024px)',
    or: '(orientation: portrait)'
}

// -----
// Context Types
// -----

interface ManagerState {
    walletManager?: WalletAuthenticationManager;
    permissionsManager?: WalletPermissionsManager;
    settingsManager?: WalletSettingsManager;
}

export interface WalletContextValue {
    // Managers:
    managers: ManagerState;
    updateManagers: (newManagers: ManagerState) => void;
    // Focus APIs:
    isFocused: () => Promise<boolean>;
    onFocusRequested: () => Promise<void>;
    onFocusRelinquished: () => Promise<void>;
    // App configuration:
    appVersion: string;
    appName: string;
    adminOriginator: string;
    // Settings
    settings: WalletSettings;
    updateSettings: (newSettings: WalletSettings) => Promise<void>;
    network: 'mainnet' | 'testnet';
    // Logout
    logout: () => void;
}

export const WalletContext = createContext<WalletContextValue>({
    managers: {},
    updateManagers: () => { },
    isFocused: async () => false,
    onFocusRequested: async () => { },
    onFocusRelinquished: async () => { },
    appVersion: packageJson.version,
    appName: 'Metanet Desktop',
    adminOriginator: 'admin.com',
    settings: DEFAULT_SETTINGS,
    updateSettings: async () => { },
    network: 'mainnet',
    logout: () => { }
})

// -----
// AuthRedirector: Handles auto-login redirect when snapshot has loaded
// -----
const AuthRedirector: React.FC<{ snapshotLoaded: boolean }> = ({ snapshotLoaded }) => {
    const history = useHistory();
    const { managers } = useContext(WalletContext);

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
    const [managers, setManagers] = useState<ManagerState>({});
    const [settings, setSettings] = useState(DEFAULT_SETTINGS);

    const updateSettings = async (newSettings: WalletSettings) => {
        if (!managers.settingsManager) {
            throw new Error('The user must be logged in to update settings!')
        }
        await managers.settingsManager.set(newSettings);
        setSettings(newSettings);
    }

    // ---- Callbacks for password/recovery/etc.
    const [passwordRetriever, setPasswordRetriever] = useState<
        (reason: string, test: (passwordCandidate: string) => boolean) => Promise<string>
    >();
    const [recoveryKeySaver, setRecoveryKeySaver] = useState<
        (key: number[]) => Promise<true>
    >();
    const [spendingAuthorizationCallback, setSpendingAuthorizationCallback] =
        useState<PermissionEventHandler>(() => { });
    const [basketAccessCallback, setBasketAccessCallback] =
        useState<PermissionEventHandler>(() => { });
    const [protocolPermissionCallback, setProtocolPermissionCallback] =
        useState<PermissionEventHandler>(() => { });
    const [certificateAccessCallback, setCertificateAccessCallback] =
        useState<PermissionEventHandler>(() => { });

    // ---- WAB + network + storage configuration ----
    const [wabUrl, setWabUrl] = useState<string>(DEFAULT_WAB_URL);
    const [wabInfo, setWabInfo] = useState<{
        supportedAuthMethods: string[];
        faucetEnabled: boolean;
        faucetAmount: number;
    } | null>(null);

    const [selectedAuthMethod, setSelectedAuthMethod] = useState<string>("");
    const [selectedNetwork, setSelectedNetwork] = useState<'main' | 'test'>(DEFAULT_CHAIN); // "test" or "main"
    const [selectedStorageUrl, setSelectedStorageUrl] = useState<string>(DEFAULT_STORAGE_URL);

    // Flag that indicates configuration is complete. For returning users,
    // if a snapshot exists we auto-mark configComplete.
    const [configComplete, setConfigComplete] = useState<boolean>(!!localStorage.snap);
    // Used to trigger a re-render after snapshot load completes.
    const [snapshotLoaded, setSnapshotLoaded] = useState<boolean>(false);
    // Flag to indicate if wallet configuration is in edit mode
    const [showWalletConfigEdit, setShowWalletConfigEdit] = useState<boolean>(false);

    // Auto-fetch WAB info and apply default configuration when component mounts
    useEffect(() => {
        if (!localStorage.snap && !configComplete) {
            (async () => {
                try {
                    // Fetch WAB info
                    const response = await fetch(`${wabUrl}/info`);
                    if (!response.ok) {
                        throw new Error(`Server responded with ${response.status}: ${response.statusText}`);
                    }

                    const info = await response.json();
                    setWabInfo(info);

                    // Auto-select the first auth method
                    if (info.supportedAuthMethods && info.supportedAuthMethods.length > 0) {
                        setSelectedAuthMethod(info.supportedAuthMethods[0]);

                        // Automatically apply default configuration
                        setConfigComplete(true);
                    }
                } catch (error: any) {
                    console.error("Error fetching WAB info", error);
                    toast.error("Could not fetch WAB info: " + error.message);
                }
            })();
        }
    }, [wabUrl, configComplete]);

    // Manual fetch WAB info function (for when user modifies the URL)
    async function fetchWabInfo() {
        try {
            const response = await fetch(`${wabUrl}/info`);
            if (!response.ok) {
                throw new Error(`Server responded with ${response.status}: ${response.statusText}`);
            }

            const info = await response.json();
            setWabInfo(info);

            // If there's only one auth method, auto-select it
            if (info.supportedAuthMethods && info.supportedAuthMethods.length === 1) {
                setSelectedAuthMethod(info.supportedAuthMethods[0]);
            }
        } catch (error: any) {
            console.error("Error fetching WAB info", error);
            toast.error("Could not fetch WAB info: " + error.message);
        }
    }

    function onSelectAuthMethod(method: string) {
        setSelectedAuthMethod(method);
    }

    // For new users: mark configuration complete when WalletConfig is submitted.
    function finalizeConfig() {
        if (!wabInfo || !selectedAuthMethod) {
            toast.error("Please select an Auth Method from the WAB info first.");
            return;
        }

        try {
            // Make sure we have all the required configuration
            if (!wabUrl) {
                toast.error("WAB Server URL is required");
                return;
            }

            if (!selectedNetwork) {
                toast.error("Network selection is required");
                return;
            }

            if (!selectedStorageUrl) {
                toast.error("Storage URL is required");
                return;
            }

            // Save the configuration
            toast.success("Default configuration applied successfully!");
            setConfigComplete(true);

            // Close the configuration dialog
            setShowWalletConfigEdit(false);
        } catch (error: any) {
            console.error("Error applying configuration:", error);
            toast.error("Failed to apply configuration: " + (error.message || "Unknown error"));
        }
    }

    // ---- Build the wallet manager once all required inputs are ready.
    useEffect(() => {
        if (
            passwordRetriever &&
            recoveryKeySaver &&
            configComplete && // either user configured or snapshot exists
            !managers.walletManager // build only once
        ) {
            try {
                // Build the wallet using user-chosen network & storage
                const walletBuilder = async (
                    primaryKey: number[],
                    privilegedKeyManager: PrivilegedKeyManager
                ): Promise<any> => {
                    try {
                        const newManagers = {} as any;
                        const chain = selectedNetwork;
                        const keyDeriver = new KeyDeriver(new PrivateKey(primaryKey));
                        const storageManager = new WalletStorageManager(keyDeriver.identityKey);
                        const signer = new WalletSigner(chain, keyDeriver, storageManager);
                        const services = new Services(chain);
                        const wallet = new Wallet(signer, services, undefined, privilegedKeyManager);
                        newManagers.settingsManager = wallet.settingsManager;

                        // Use user-selected storage provider
                        const client = new StorageClient(wallet, selectedStorageUrl);
                        await client.makeAvailable();
                        await storageManager.addWalletStorageProvider(client);

                        // Setup permissions with provided callbacks.
                        const permissionsManager = new WalletPermissionsManager(wallet, adminOriginator, {
                            seekPermissionsForPublicKeyRevelation: false,
                            seekProtocolPermissionsForSigning: false,
                            seekProtocolPermissionsForEncrypting: false,
                            seekProtocolPermissionsForHMAC: false,
                            seekPermissionsForIdentityKeyRevelation: false,
                            seekPermissionsForKeyLinkageRevelation: false
                        });

                        if (protocolPermissionCallback) {
                            permissionsManager.bindCallback('onProtocolPermissionRequested', protocolPermissionCallback);
                        }
                        if (basketAccessCallback) {
                            permissionsManager.bindCallback('onBasketAccessRequested', basketAccessCallback);
                        }
                        if (spendingAuthorizationCallback) {
                            permissionsManager.bindCallback('onSpendingAuthorizationRequested', spendingAuthorizationCallback);
                        }
                        if (certificateAccessCallback) {
                            permissionsManager.bindCallback('onCertificateAccessRequested', certificateAccessCallback);
                        }

                        // Store in window for debugging
                        (window as any).permissionsManager = permissionsManager;
                        newManagers.permissionsManager = permissionsManager;

                        setManagers(m => ({ ...m, ...newManagers }));

                        return permissionsManager;
                    } catch (error: any) {
                        console.error("Error building wallet:", error);
                        toast.error("Failed to build wallet: " + error.message);
                        return null;
                    }
                };

                // Create network service based on selected network
                const networkPreset = selectedNetwork === 'main' ? 'mainnet' : 'testnet';

                // Create a LookupResolver instance
                const resolver = new LookupResolver({
                    networkPreset
                });

                // Create a broadcaster with proper network settings
                const broadcaster = new SHIPBroadcaster(['tm_users'], {
                    networkPreset
                });

                // Create a WAB Client with proper URL
                const wabClient = new WABClient(wabUrl);

                // Create a phone interactor
                const phoneInteractor = new TwilioPhoneInteractor();

                // Create the wallet manager with proper error handling
                const exampleWalletManager = new WalletAuthenticationManager(
                    adminOriginator,
                    walletBuilder,
                    new OverlayUMPTokenInteractor(
                        resolver,
                        broadcaster
                    ),
                    recoveryKeySaver,
                    passwordRetriever,
                    // Type assertions needed due to interface mismatch between our WABClient and the expected SDK client
                    wabClient,
                    phoneInteractor
                );

                // Store in window for debugging
                (window as any).walletManager = exampleWalletManager;

                // Set initial managers state to prevent null references
                setManagers(m => ({ ...m, walletManager: exampleWalletManager }));

                // Fire the parent callback to let parent components know
                // that the wallet is ready
                if (onWalletReady) {
                    onWalletReady(exampleWalletManager);
                }

                // If a snapshot exists, attempt to load it and mark snapshotLoaded true on success.
                if (localStorage.snap) {
                    const snapArr = Utils.toArray(localStorage.snap, 'base64');
                    exampleWalletManager.loadSnapshot(snapArr)
                        .then(() => {
                            console.log("Snapshot loaded successfully");
                            setSnapshotLoaded(true);
                        })
                        .catch((err: any) => {
                            console.error("Error loading snapshot", err);
                            localStorage.removeItem('snap'); // Clear invalid snapshot
                            toast.error("Couldn't load saved data: " + err.message);
                        });
                }

            } catch (err: any) {
                console.error("Error initializing wallet manager:", err);
                toast.error("Failed to initialize wallet: " + err.message);
                // Reset configuration if wallet initialization fails
                setConfigComplete(false);
            }
        }
    }, [
        passwordRetriever,
        recoveryKeySaver,
        configComplete,
        managers.walletManager,
        selectedNetwork,
        selectedStorageUrl,
        adminOriginator,
        protocolPermissionCallback,
        basketAccessCallback,
        spendingAuthorizationCallback,
        certificateAccessCallback,
        wabUrl,
        onWalletReady
    ]);

    // When Settings manager becomes available, populate the user's settings
    useEffect(() => {
        (async () => {
            if (managers.settingsManager) {
                try {
                    const settings = await managers.settingsManager.get();
                    setSettings(settings);
                } catch (e) {
                    // Unable to load settings, defaults are already loaded.
                }
            }
        })();
    }, [managers])

    // For new users, show the WalletConfig if no snapshot exists.
    const noManagerYet = !managers.walletManager;

    const logout = () => {
        // Clear localStorage to prevent auto-login
        if (localStorage.snap) {
            localStorage.removeItem('snap');
        }

        // Reset manager state
        setManagers({});

        // Reset configuration state
        setConfigComplete(false);
        setSnapshotLoaded(false);
    };

    const contextValue = useMemo(() => ({
        managers,
        updateManagers: (newManagers: ManagerState) => setManagers(newManagers),
        isFocused: isFocused || (() => Promise.resolve(true)),
        onFocusRequested: requestFocus || (() => Promise.resolve()),
        onFocusRelinquished: relinquishFocus || (() => Promise.resolve()),
        appName,
        appVersion,
        adminOriginator,
        settings,
        updateSettings,
        network: selectedNetwork === 'main' ? 'mainnet' : 'testnet' as 'mainnet' | 'testnet',
        logout
    }), [
        managers,
        isFocused,
        requestFocus,
        relinquishFocus,
        appName,
        appVersion,
        adminOriginator,
        settings,
        selectedNetwork,
        logout
    ])

    return (
        <WalletContext.Provider
            value={contextValue}
        >
            <Router>
                {/* This component handles redirecting once the snapshot is loaded and authentication is valid */}
                <AuthRedirector snapshotLoaded={snapshotLoaded} />
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
                                    <Route path='/welcome' component={Welcome} />
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
