import React, { useState, useEffect, createContext, useContext } from 'react'
import {
    Wallet,
    WalletPermissionsManager,
    PrivilegedKeyManager,
    Services,
    StorageClient,
    WalletSigner,
    WalletStorageManager,
    PermissionEventHandler,
    WalletAuthenticationManager,
    OverlayUMPTokenInteractor
} from '@bsv/wallet-toolbox-client'
import {
    KeyDeriver,
    LookupResolver,
    PrivateKey,
    SHIPBroadcaster,
    Utils,
    WalletInterface
} from '@bsv/sdk'
import PasswordHandler from './components/PasswordHandler'
import RecoveryKeyHandler from './components/RecoveryKeyHandler'
import SpendingAuthorizationHandler from './components/SpendingAuthorizationHandler'
import ProtocolPermissionHandler from './components/ProtocolPermissionHandler'
import CertificateAccessHandler from './components/CertificateAccessHandler'
import Theme from './components/Theme'
import { ExchangeRateContextProvider } from './components/AmountDisplay/ExchangeRateContextProvider'
import { DEFAULT_SETTINGS, WalletSettings, WalletSettingsManager } from '@bsv/wallet-toolbox-client/out/src/WalletSettingsManager'
import { MemoryRouter as Router, Switch, Route, useHistory } from 'react-router-dom'
import { ToastContainer } from 'react-toastify'
import 'react-toastify/dist/ReactToastify.css'
import BasketAccessHandler from './components/BasketAccessHandler'
import { BreakpointProvider } from './utils/useBreakpoints'
import UserTheme from './components/UserTheme'

import Greeter from './pages/Greeter'
import Welcome from './pages/Welcome'
import Recovery from './pages/Recovery'
import LostPhone from './pages/Recovery/LostPhone'
import LostPassword from './pages/Recovery/LostPassword'
import Dashboard from './pages/Dashboard'
import { Chain } from '@bsv/wallet-toolbox-client/out/src/sdk'
import { WABClient, TwilioPhoneInteractor } from '@bsv/wallet-toolbox-client'
import WalletConfig from './components/WalletConfig'

/** Defaults */
const STORAGE_URL = 'https://storage.babbage.systems'
const CHAIN = 'main'

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
    updateSettings: (newSettings: WalletSettings) => void;
    network: 'mainnet' | 'testnet';
}

export const WalletContext = createContext<WalletContextValue>({
    managers: {},
    updateManagers: () => { },
    isFocused: async () => false,
    onFocusRequested: async () => { },
    onFocusRelinquished: async () => { },
    appVersion: '0.0.0',
    appName: 'MetaNet Client',
    adminOriginator: 'admin.com',
    settings: DEFAULT_SETTINGS,
    updateSettings: () => { },
    network: 'mainnet'
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
    onWalletReady: (wallet: WalletInterface) => void;
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
    appVersion = '0.0.0',
    appName = 'MetaNet Client'
}) => {
    const [managers, updateManagers] = useState<ManagerState>({});
    const [settings, setLocalSettings] = useState(DEFAULT_SETTINGS);

    const updateSettings = async (newSettings: WalletSettings) => {
        if (!managers.settingsManager) {
            throw new Error('The user must be logged in to update settings!')
        }
        await managers.settingsManager.set(newSettings);
        setLocalSettings(newSettings);
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
    const [wabUrl, setWabUrl] = useState<string>("https://wab.babbage.systems");
    const [wabInfo, setWabInfo] = useState<{
        supportedAuthMethods: string[];
        faucetEnabled: boolean;
        faucetAmount: number;
    } | null>(null);

    const [selectedAuthMethod, setSelectedAuthMethod] = useState<string>("");
    const [selectedNetwork, setSelectedNetwork] = useState<'main' | 'test'>(CHAIN); // "test" or "main"
    const [selectedStorageUrl, setSelectedStorageUrl] = useState<string>(STORAGE_URL);

    // Flag that indicates configuration is complete. For returning users,
    // if a snapshot exists we auto-mark configComplete.
    const [configComplete, setConfigComplete] = useState<boolean>(!!localStorage.snap);
    // Used to trigger a re-render after snapshot load completes.
    const [snapshotLoaded, setSnapshotLoaded] = useState<boolean>(false);

    async function fetchWabInfo() {
        try {
            const res = await fetch(`${wabUrl}/info`);
            if (!res.ok) {
                throw new Error(`Failed to fetch info: ${res.status}`);
            }
            const info = await res.json();
            setWabInfo(info);
        } catch (error: any) {
            console.error("Error fetching WAB info", error);
            alert("Could not fetch WAB info: " + error.message);
        }
    }

    function onSelectAuthMethod(method: string) {
        setSelectedAuthMethod(method);
    }

    // For new users: mark configuration complete when WalletConfig is submitted.
    function finalizeConfig() {
        if (!wabInfo || !selectedAuthMethod) {
            alert("Please select an Auth Method from the WAB info first.");
            return;
        }
        setConfigComplete(true);
    }

    // ---- Build the wallet manager once all required inputs are ready.
    useEffect(() => {
        if (
            passwordRetriever &&
            recoveryKeySaver &&
            configComplete && // either user configured or snapshot exists
            !managers.walletManager // build only once
        ) {
            // Build the wallet using user-chosen network & storage
            const walletBuilder = async (
                primaryKey: number[],
                privilegedKeyManager: PrivilegedKeyManager
            ): Promise<WalletInterface> => {
                const chain = selectedNetwork;
                const keyDeriver = new KeyDeriver(new PrivateKey(primaryKey));
                const storageManager = new WalletStorageManager(keyDeriver.identityKey);
                const signer = new WalletSigner(chain as Chain, keyDeriver, storageManager);
                const services = new Services(chain as Chain);
                const wallet = new Wallet(signer, services, undefined, privilegedKeyManager);
                const settingsManager = wallet.settingsManager;

                // Use user-selected storage provider
                const client = new StorageClient(wallet, selectedStorageUrl);
                await client.makeAvailable();
                await storageManager.addWalletStorageProvider(client);

                // Setup permissions with provided callbacks.
                const permissionsManager = new WalletPermissionsManager(wallet, adminOriginator, {
                    // TODO: Re-enable permissions once they are fully working.
                    seekPermissionsForPublicKeyRevelation: false,
                    seekProtocolPermissionsForSigning: false,
                    seekProtocolPermissionsForEncrypting: false,
                    seekProtocolPermissionsForHMAC: false,
                    seekPermissionsForIdentityKeyRevelation: false,
                    seekPermissionsForKeyLinkageRevelation: false
                });
                permissionsManager.bindCallback('onProtocolPermissionRequested', protocolPermissionCallback);
                permissionsManager.bindCallback('onBasketAccessRequested', basketAccessCallback);
                permissionsManager.bindCallback('onSpendingAuthorizationRequested', spendingAuthorizationCallback);
                permissionsManager.bindCallback('onCertificateAccessRequested', certificateAccessCallback);

                (window as any).permissionsManager = permissionsManager;

                updateManagers({
                    walletManager: exampleWalletManager,
                    permissionsManager,
                    settingsManager
                });

                return permissionsManager;
            };

            debugger
            const resolver = new LookupResolver({
                networkPreset: selectedNetwork === 'main' ? 'mainnet' : 'testnet',
                hostOverrides: {
                    'ls_ship': ['https://users.bapp.dev'],
                    'ls_users': ['https://users.bapp.dev']
                },
                slapTrackers: ['https://users.bapp.dev']
            })

            const exampleWalletManager = new WalletAuthenticationManager(
                adminOriginator,
                walletBuilder,
                new OverlayUMPTokenInteractor(
                    resolver,
                    new SHIPBroadcaster(['tm_users'], {
                        networkPreset: selectedNetwork === 'main' ? 'mainnet' : 'testnet',
                        resolver
                    })
                ),
                recoveryKeySaver,
                passwordRetriever,
                new WABClient(wabUrl),
                new TwilioPhoneInteractor()
            );
            (window as any).authManager = exampleWalletManager;

            // If a snapshot exists, attempt to load it and mark snapshotLoaded true on success.
            if (localStorage.snap) {
                const snapArr = Utils.toArray(localStorage.snap, 'base64');
                exampleWalletManager.loadSnapshot(snapArr)
                    .then(() => {
                        console.log("Snapshot loaded successfully");
                        setSnapshotLoaded(true);
                    })
                    .catch((err) => {
                        console.error("Failed to load snapshot from localStorage", err);
                    });
            }

            // Fire the parent callback and update context.
            onWalletReady(exampleWalletManager);
            updateManagers({ walletManager: exampleWalletManager });
        }
    }, [
        passwordRetriever,
        recoveryKeySaver,
        configComplete,
        managers.walletManager,
        wabUrl,
        selectedNetwork,
        selectedStorageUrl,
        selectedAuthMethod,
        onWalletReady,
        updateManagers,
        protocolPermissionCallback,
        basketAccessCallback,
        spendingAuthorizationCallback,
        certificateAccessCallback
    ]);

    // When Settings manager becomes available, populate the user's settings
    useEffect(() => {
        (async () => {
            if (managers.settingsManager) {
                try {
                    const settings = await managers.settingsManager.get();
                    setLocalSettings(settings);
                } catch (e) {
                    // Unable to load settings, defaaults are already loaded.
                }
            }
        })();
    }, [managers])

    // For new users, show the WalletConfig if no snapshot exists.
    const noManagerYet = !managers.walletManager;

    return (
        <WalletContext.Provider
            value={{
                managers,
                updateManagers,
                isFocused: isFocused ? isFocused : async () => false,
                onFocusRequested: requestFocus ? requestFocus : async () => { },
                onFocusRelinquished: relinquishFocus ? relinquishFocus : async () => { },
                appName,
                appVersion,
                adminOriginator,
                settings,
                updateSettings,
                network: selectedNetwork === 'main' ? 'mainnet' : 'testnet'
            }}
        >
            <UserTheme>
                <Router>
                    {/* This component handles redirecting once the snapshot is loaded and authentication is valid */}
                    <AuthRedirector snapshotLoaded={snapshotLoaded} />
                    <ExchangeRateContextProvider>
                        <BreakpointProvider queries={queries}>
                            <Theme>
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

                                {/* Render configuration UI only if no snapshot is present */}
                                {(noManagerYet || !(managers.walletManager as any)?.authenticated) && !localStorage.snap && (
                                    <WalletConfig
                                        noManagerYet={noManagerYet}
                                        wabUrl={wabUrl}
                                        setWabUrl={setWabUrl}
                                        fetchWabInfo={fetchWabInfo}
                                        wabInfo={wabInfo!}
                                        selectedAuthMethod={selectedAuthMethod}
                                        onSelectAuthMethod={onSelectAuthMethod}
                                        selectedNetwork={selectedNetwork}
                                        setSelectedNetwork={setSelectedNetwork}
                                        selectedStorageUrl={selectedStorageUrl}
                                        setSelectedStorageUrl={setSelectedStorageUrl}
                                        finalizeConfig={finalizeConfig}
                                    />
                                )}

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
                            </Theme>
                        </BreakpointProvider>
                    </ExchangeRateContextProvider>
                </Router>
            </UserTheme>
        </WalletContext.Provider>
    )
}
