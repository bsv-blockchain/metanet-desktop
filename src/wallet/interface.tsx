import {
  WalletInterface,
  CreateActionArgs,
  SignActionArgs,
  AbortActionArgs,
  ListActionsArgs,
  InternalizeActionArgs,
  ListOutputsArgs,
  RelinquishOutputArgs,
  GetPublicKeyArgs,
  RevealCounterpartyKeyLinkageArgs,
  RevealSpecificKeyLinkageArgs,
  WalletEncryptArgs,
  WalletDecryptArgs,
  CreateHmacArgs,
  VerifyHmacArgs,
  CreateSignatureArgs,
  VerifySignatureArgs,
  AcquireCertificateArgs,
  ListCertificatesArgs,
  ProveCertificateArgs,
  RelinquishCertificateArgs,
  DiscoverByIdentityKeyArgs,
  DiscoverByAttributesArgs,
  GetHeaderArgs,
} from '@bsv/sdk';
import { listen, emit } from '@tauri-apps/api/event'

// Type definitions for request and response handling
type RequestHeaders = Record<string, string>;

interface WalletRequest {
  method: string;
  path: string;
  headers: RequestHeaders;
  body: string;
  request_id: string;
}

interface WalletResponse {
  request_id: string;
  status: number;
  body: string;
}

// Define the handler function type
type RequestHandler = (request: WalletRequest, wallet: WalletInterface) => Promise<any>;

/**
 * Creates a wallet endpoint handler function with standardized error handling
 */
const createHandler = <T, R>(
  handlerFn: (args: T, origin: string, wallet: WalletInterface) => Promise<R>
): RequestHandler => {
  return async (req: WalletRequest, wallet: WalletInterface): Promise<R> => {
    try {
      const args = req.body ? JSON.parse(req.body) as T : {} as T;
      return await handlerFn(args, req.headers['origin'], wallet);
    } catch (error) {
      console.error(`Handler error:`, error);
      throw error;
    }
  };
};

/**
 * Maps API paths to their handler functions
 */
const createEndpointMap = (wallet: WalletInterface): Record<string, RequestHandler> => {
  return {
    // Action endpoints
    '/createAction': createHandler<CreateActionArgs, any>(
      (args, origin, wallet) => wallet.createAction(args, origin)
    ),
    '/signAction': createHandler<SignActionArgs, any>(
      (args, origin, wallet) => wallet.signAction(args, origin)
    ),
    '/abortAction': createHandler<AbortActionArgs, any>(
      (args, origin, wallet) => wallet.abortAction(args, origin)
    ),
    '/listActions': createHandler<ListActionsArgs, any>(
      (args, origin, wallet) => wallet.listActions(args, origin)
    ),
    '/internalizeAction': createHandler<InternalizeActionArgs, any>(
      (args, origin, wallet) => wallet.internalizeAction(args, origin)
    ),

    // Output endpoints
    '/listOutputs': createHandler<ListOutputsArgs, any>(
      (args, origin, wallet) => wallet.listOutputs(args, origin)
    ),
    '/relinquishOutput': createHandler<RelinquishOutputArgs, any>(
      (args, origin, wallet) => wallet.relinquishOutput(args, origin)
    ),

    // Key endpoints
    '/getPublicKey': createHandler<GetPublicKeyArgs, any>(
      (args, origin, wallet) => wallet.getPublicKey(args, origin)
    ),
    '/revealCounterpartyKeyLinkage': createHandler<RevealCounterpartyKeyLinkageArgs, any>(
      (args, origin, wallet) => wallet.revealCounterpartyKeyLinkage(args, origin)
    ),
    '/revealSpecificKeyLinkage': createHandler<RevealSpecificKeyLinkageArgs, any>(
      (args, origin, wallet) => wallet.revealSpecificKeyLinkage(args, origin)
    ),

    // Encryption endpoints
    '/encrypt': createHandler<WalletEncryptArgs, any>(
      (args, origin, wallet) => wallet.encrypt(args, origin)
    ),
    '/decrypt': createHandler<WalletDecryptArgs, any>(
      (args, origin, wallet) => wallet.decrypt(args, origin)
    ),

    // HMAC endpoints
    '/createHmac': createHandler<CreateHmacArgs, any>(
      (args, origin, wallet) => wallet.createHmac(args, origin)
    ),
    '/verifyHmac': createHandler<VerifyHmacArgs, any>(
      (args, origin, wallet) => wallet.verifyHmac(args, origin)
    ),

    // Signature endpoints
    '/createSignature': createHandler<CreateSignatureArgs, any>(
      (args, origin, wallet) => wallet.createSignature(args, origin)
    ),
    '/verifySignature': createHandler<VerifySignatureArgs, any>(
      (args, origin, wallet) => wallet.verifySignature(args, origin)
    ),

    // Certificate endpoints
    '/acquireCertificate': createHandler<AcquireCertificateArgs, any>(
      (args, origin, wallet) => wallet.acquireCertificate(args, origin)
    ),
    '/listCertificates': createHandler<ListCertificatesArgs, any>(
      (args, origin, wallet) => wallet.listCertificates(args, origin)
    ),
    '/proveCertificate': createHandler<ProveCertificateArgs, any>(
      (args, origin, wallet) => wallet.proveCertificate(args, origin)
    ),
    '/relinquishCertificate': createHandler<RelinquishCertificateArgs, any>(
      (args, origin, wallet) => wallet.relinquishCertificate(args, origin)
    ),

    // Discovery endpoints
    '/discoverByIdentityKey': createHandler<DiscoverByIdentityKeyArgs, any>(
      (args, origin, wallet) => wallet.discoverByIdentityKey(args, origin)
    ),
    '/discoverByAttributes': createHandler<DiscoverByAttributesArgs, any>(
      (args, origin, wallet) => wallet.discoverByAttributes(args, origin)
    ),

    // Auth endpoints
    '/isAuthenticated': createHandler<{}, any>(
      (args, origin, wallet) => wallet.isAuthenticated(args, origin)
    ),
    '/waitForAuthentication': createHandler<{}, any>(
      (args, origin, wallet) => wallet.waitForAuthentication(args, origin)
    ),

    // Blockchain endpoints
    '/getHeight': createHandler<{}, any>(
      (args, origin, wallet) => wallet.getHeight(args, origin)
    ),
    '/getHeaderForHeight': createHandler<GetHeaderArgs, any>(
      (args, origin, wallet) => wallet.getHeaderForHeight(args, origin)
    ),
    '/getNetwork': createHandler<{}, any>(
      (args, origin, wallet) => wallet.getNetwork(args, origin)
    ),
    '/getVersion': createHandler<{}, any>(
      (args, origin, wallet) => wallet.getVersion(args, origin)
    ),
  };
};

/**
 * Processes incoming HTTP requests, routes them to the appropriate handler,
 * and returns a formatted response
 */
const processRequest = async (
  req: WalletRequest, 
  endpointMap: Record<string, RequestHandler>,
  wallet: WalletInterface
): Promise<WalletResponse> => {
  try {
    // Check for origin header
    if (!req.headers['origin']) {
      return {
        request_id: req.request_id,
        status: 400,
        body: JSON.stringify({ message: 'Origin header is required' })
      };
    }

    // Find appropriate handler for the path
    const handler = endpointMap[req.path];
    if (!handler) {
      return {
        request_id: req.request_id,
        status: 404,
        body: JSON.stringify({ error: 'Unknown wallet path: ' + req.path })
      };
    }

    // Execute handler and return successful response
    const result = await handler(req, wallet);
    return {
      request_id: req.request_id,
      status: 200,
      body: JSON.stringify(result)
    };
  } catch (error) {
    // Handle errors with a 400 response
    return {
      request_id: req.request_id,
      status: 400,
      body: JSON.stringify({
        message: error instanceof Error ? error.message : String(error)
      })
    };
  }
};

/**
 * Normalizes request headers to lowercase
 */
const normalizeRequestHeaders = (req: WalletRequest): WalletRequest => {
  // Convert headers to lowercase map
  const headers = Object.fromEntries(
    (req.headers as unknown as string[][]).map(([k, v]) => [k.toLowerCase(), v])
  );
  
  // Set origin from originator if it exists
  if (headers.originator && !headers.origin) {
    headers.origin = headers.originator;
  }
  
  return { ...req, headers };
};

/**
 * Bridge between Tauri events and wallet functionality
 */
export const WalletBridge = async (wallet: WalletInterface) => {
  // Set up wallet for debugging
  (window as any).externallyCallableWallet = wallet;
  console.log('THE INTERFACE IS UP! WALLET:', wallet);
  
  // Create endpoint map once
  const endpointMap = createEndpointMap(wallet);

  // Listen for HTTP requests from the Rust backend
  await listen('http-request', async (event) => {
    try {
      // Parse and normalize the request
      let req = JSON.parse(event.payload as string) as WalletRequest;
      console.log("Received HTTP request:", {
        method: req.method,
        path: req.path,
        request_id: req.request_id
      });
      
      // Normalize headers
      req = normalizeRequestHeaders(req);
      
      // Process the request
      const response = await processRequest(req, endpointMap, wallet);
      
      // Send response back to Rust
      emit('ts-response', response);
    } catch (error) {
      console.error("Error handling request:", error);
    }
  });
};