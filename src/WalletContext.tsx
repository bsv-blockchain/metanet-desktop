import React, { useState, useEffect, createContext, useMemo, useCallback, useContext } from 'react'
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
    WABClient,
    PermissionRequest
} from '@bsv/wallet-toolbox-client'
import {
    KeyDeriver,
    PrivateKey,
    SHIPBroadcaster,
    Utils,
    LookupResolver
} from '@bsv/sdk'
import { DEFAULT_SETTINGS, WalletSettings, WalletSettingsManager } from '@bsv/wallet-toolbox-client/out/src/WalletSettingsManager'
import { toast } from 'react-toastify'
import 'react-toastify/dist/ReactToastify.css'
import { WalletBridge } from './wallet/interface'
import { DEFAULT_WAB_URL, DEFAULT_STORAGE_URL, DEFAULT_CHAIN, ADMIN_ORIGINATOR } from './config'
import { UserContext } from './UserContext'

// Define a type for the config from WalletConfig component
type WalletConfigType = {
    wabUrl: string;
    selectedAuthMethod: string;
    selectedNetwork: 'main' | 'test';
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
    // Settings
    settings: WalletSettings;
    updateSettings: (newSettings: WalletSettings) => Promise<void>;
    network: 'mainnet' | 'testnet';
    // Logout
    logout: () => void;
    adminOriginator: string;
    setPasswordRetriever: (retriever: (reason: string, test: (passwordCandidate: string) => boolean) => Promise<string>) => void
    setRecoveryKeySaver: (saver: (key: number[]) => Promise<true>) => void
    setSpendingAuthorizationCallback: (callback: PermissionEventHandler) => void
    setProtocolPermissionCallback: (callback: PermissionEventHandler) => void
    snapshotLoaded: boolean
    requests: BasketAccessRequest[]
    advanceQueue: () => void
}

export const WalletContext = createContext<WalletContextValue>({
    managers: {},
    updateManagers: () => { },
    settings: DEFAULT_SETTINGS,
    updateSettings: async () => { },
    network: 'mainnet',
    logout: () => { },
    adminOriginator: ADMIN_ORIGINATOR,
    setPasswordRetriever: () => { },
    setRecoveryKeySaver: () => { },
    setSpendingAuthorizationCallback: () => { },
    setProtocolPermissionCallback: () => { },
    snapshotLoaded: false,
    requests: [],
    advanceQueue: () => { }
})

interface WalletContextProps {
    children?: React.ReactNode;
}


type BasketAccessRequest = {
    requestID: string
    basket?: string
    originator: string
    reason?: string
    renewal?: boolean
}

export const WalletContextProvider: React.FC<WalletContextProps> = ({
    children
}) => {
    const [managers, setManagers] = useState<ManagerState>({});
    const [settings, setSettings] = useState(DEFAULT_SETTINGS);
    const [adminOriginator, setAdminOriginator] = useState(ADMIN_ORIGINATOR);
    const { isFocused, onFocusRequested, onFocusRelinquished, setBasketAccessModalOpen } = useContext(UserContext);

    // Track if we were originally focused
    const [wasOriginallyFocused, setWasOriginallyFocused] = useState(false)

    // This array will queue up multiple requests
    const [requests, setRequests] = useState<BasketAccessRequest[]>([])

    // Pop the first request from the queue, close if empty, relinquish focus if needed
    const advanceQueue = () => {
        setRequests(prev => {
            const newQueue = prev.slice(1)
            if (newQueue.length === 0) {
                setBasketAccessModalOpen(false)
                if (!wasOriginallyFocused) {
                    onFocusRelinquished()
                }
            }
            return newQueue
        })
    }

    const updateSettings = useCallback(async (newSettings: WalletSettings) => {
        if (!managers.settingsManager) {
            throw new Error('The user must be logged in to update settings!')
        }
        await managers.settingsManager.set(newSettings);
        setSettings(newSettings);
    }, [managers.settingsManager]);

    // ---- Callbacks for password/recovery/etc.
    const [passwordRetriever, setPasswordRetriever] = useState<
        (reason: string, test: (passwordCandidate: string) => boolean) => Promise<string>
    >();
    const [recoveryKeySaver, setRecoveryKeySaver] = useState<
        (key: number[]) => Promise<true>
    >();
    const [spendingAuthorizationCallback, setSpendingAuthorizationCallback] =
        useState<PermissionEventHandler>(() => { });
    const [protocolPermissionCallback, setProtocolPermissionCallback] =
        useState<PermissionEventHandler>(() => { });
    const [certificateAccessCallback, setCertificateAccessCallback] =
        useState<PermissionEventHandler>(() => { });


    // Provide a handler for basket-access requests that enqueues them
    const basketAccessCallback = useCallback((incomingRequest: PermissionRequest & {
        requestID: string
        basket?: string
        originator: string
        reason?: string
        renewal?: boolean
    }, ...args: any) => {
        console.log({ incomingRequest })
        // Enqueue the new request
        if(incomingRequest?.requestID) {
            setRequests(prev => {
                const wasEmpty = prev.length === 0

                // If no requests were queued, handle focusing logic right away
                if (wasEmpty) {
                    isFocused().then(currentlyFocused => {
                        setWasOriginallyFocused(currentlyFocused)
                        if (!currentlyFocused) {
                            onFocusRequested()
                        }
                        setBasketAccessModalOpen(true)
                    })
                }

                return [
                    ...prev,
                    {
                        requestID: incomingRequest.requestID,
                        basket: incomingRequest.basket,
                        originator: incomingRequest.originator,
                        reason: incomingRequest.reason,
                        renewal: incomingRequest.renewal
                    }
                ]
            })
        }
    }, [isFocused, onFocusRequested])

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

    // Fetch WAB info for first-time configuration
    const fetchWabInfo = useCallback(async () => {
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
            return info;
        } catch (error: any) {
            console.error("Error fetching WAB info", error);
            toast.error("Could not fetch WAB info: " + error.message);
            return null;
        }
    }, [wabUrl]);

    // Auto-fetch WAB info and apply default configuration when component mounts
    useEffect(() => {
        if (!localStorage.snap && !configComplete) {
            (async () => {
                try {
                    const info = await fetchWabInfo();
                    
                    if (info && info.supportedAuthMethods && info.supportedAuthMethods.length > 0) {
                        setSelectedAuthMethod(info.supportedAuthMethods[0]);
                        // Automatically apply default configuration
                        setConfigComplete(true);
                    }
                } catch (error: any) {
                    console.error("Error in initial WAB setup", error);
                }
            })();
        }
    }, [wabUrl, configComplete, fetchWabInfo]);

    const onSelectAuthMethod = useCallback((method: string) => {
        setSelectedAuthMethod(method);
    }, []);

    // For new users: mark configuration complete when WalletConfig is submitted.
    const finalizeConfig = useCallback(() => {
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
    }, [wabInfo, selectedAuthMethod, wabUrl, selectedNetwork, selectedStorageUrl]);

    // Build wallet function
    const buildWallet = useCallback(async (
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
            const permissionsManager = new WalletPermissionsManager(wallet, ADMIN_ORIGINATOR, {
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
    }, [
        selectedNetwork,
        selectedStorageUrl,
        adminOriginator,
        protocolPermissionCallback,
        basketAccessCallback,
        spendingAuthorizationCallback,
        certificateAccessCallback
    ]);

    // Load snapshot function
    const loadWalletSnapshot = useCallback(async (walletManager: WalletAuthenticationManager) => {
        if (localStorage.snap) {
            try {
                const snapArr = Utils.toArray(localStorage.snap, 'base64');
                await walletManager.loadSnapshot(snapArr);
                console.log("Snapshot loaded successfully");
                setSnapshotLoaded(true);
            } catch (err: any) {
                console.error("Error loading snapshot", err);
                localStorage.removeItem('snap'); // Clear invalid snapshot
                toast.error("Couldn't load saved data: " + err.message);
            }
        }
    }, []);

    // ---- Build the wallet manager once all required inputs are ready.
    useEffect(() => {
        console.log('building the wallet for the first time', passwordRetriever, recoveryKeySaver, configComplete, managers.walletManager, adminOriginator)
        if (
            configComplete && // either user configured or snapshot exists
            !managers.walletManager // build only once
        ) {
            try {

                console.log('createnetwork')   
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
                    buildWallet,
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
                if (WalletBridge) {
                    WalletBridge(exampleWalletManager);
                }

                // Load snapshot if available
                loadWalletSnapshot(exampleWalletManager);

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
        wabUrl,
        WalletBridge,
        buildWallet,
        loadWalletSnapshot,
        adminOriginator
    ]);

    // When Settings manager becomes available, populate the user's settings
    useEffect(() => {
        const loadSettings = async () => {
            if (managers.settingsManager) {
                try {
                    const userSettings = await managers.settingsManager.get();
                    setSettings(userSettings);
                } catch (e) {
                    // Unable to load settings, defaults are already loaded.
                }
            }
        };
        
        loadSettings();
    }, [managers]);

    const logout = useCallback(() => {
        // Clear localStorage to prevent auto-login
        if (localStorage.snap) {
            localStorage.removeItem('snap');
        }

        // Reset manager state
        setManagers({});

        // Reset configuration state
        setConfigComplete(false);
        setSnapshotLoaded(false);
    }, []);

    const wallet = useMemo(() => ({
        managers,
        updateManagers: (newManagers: ManagerState) => setManagers(prev => ({ ...prev, ...newManagers })),
        settings,
        updateSettings,
        network: selectedNetwork === 'main' ? 'mainnet' : 'testnet' as 'mainnet' | 'testnet',
        logout,
        adminOriginator: ADMIN_ORIGINATOR,
        snapshotLoaded,
        setPasswordRetriever,
        setRecoveryKeySaver,
        setSpendingAuthorizationCallback,
        setProtocolPermissionCallback,
        setCertificateAccessCallback,
        requests,
        advanceQueue
    }), [
        managers,
        settings,
        updateSettings,
        selectedNetwork,
        logout,
    ]);

    return <WalletContext.Provider value={wallet}>
        {children}
    </WalletContext.Provider>
}
