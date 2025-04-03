import { Dispatch, SetStateAction, useState, useEffect, useContext } from 'react'
import { DialogContent, DialogActions, Button, Box, Stack, Tooltip, Avatar, Divider } from '@mui/material'
import CustomDialog from '../CustomDialog/index'
import { WalletContext } from '../../WalletContext'
import { UserContext } from '../../UserContext'
import AppChip from '../AppChip/index'
import ProtoChip from '../ProtoChip/index'
import { PermissionEventHandler, PermissionRequest } from '@bsv/wallet-toolbox-client'
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser'
import CodeIcon from '@mui/icons-material/Code'
import CachedIcon from '@mui/icons-material/Cached'
import ShoppingBasketIcon from '@mui/icons-material/ShoppingBasket'
import deterministicColor from '../../utils/deterministicColor'

// Permission request types
type PermissionType = 'identity' | 'protocol' | 'renewal' | 'basket';

interface PermissionItem {
  requestID: string;
  protocolSecurityLevel: number;
  protocolID: string;
  counterparty?: string;
  originator?: string;
  description?: string;
  renewal?: boolean;
  type?: PermissionType;
}

const ProtocolPermissionHandler: React.FC<{
  setProtocolPermissionCallback: Dispatch<SetStateAction<PermissionEventHandler>>
}> = ({ setProtocolPermissionCallback }) => {
  const { managers } = useContext(WalletContext)
  const { onFocusRequested, onFocusRelinquished, isFocused } = useContext(UserContext)
  const [wasOriginallyFocused, setWasOriginallyFocused] = useState(false)
  const [open, setOpen] = useState(false)
  const [perms, setPerms] = useState<Array<PermissionItem>>([])

  const handleCancel = () => {
    managers.permissionsManager.denyPermission(perms[0].requestID)
    setPerms(prev => {
      const newPerms = prev.slice(1)
      if (newPerms.length === 0) {
        setOpen(false)
        if (!wasOriginallyFocused) {
          onFocusRelinquished()
        }
      }
      return newPerms
    })
  }

  const handleGrant = () => {
    managers.permissionsManager.grantPermission({ requestID: perms[0].requestID })
    setPerms(prev => {
      const newPerms = prev.slice(1)
      if (newPerms.length === 0) {
        setOpen(false)
        if (!wasOriginallyFocused) {
          onFocusRelinquished()
        }
      }
      return newPerms
    })
  }

  useEffect(() => {
    setProtocolPermissionCallback(() => {
      return async (args: PermissionRequest & { requestID: string }): Promise<void> => {
        const {
          requestID,
          counterparty,
          originator,
          reason,
          renewal,
          protocolID
        } = args
        const [protocolSecurityLevel, protocolNameString] = protocolID!
        
        // First check if we're already focused
        const wasOriginallyFocused = await isFocused()
        
        // Determine type of permission
        let permissionType: PermissionType = 'protocol';
        if (protocolNameString === 'identity resolution') {
          permissionType = 'identity';
        } else if (renewal) {
          permissionType = 'renewal';
        } else if (protocolNameString.includes('basket')) {
          permissionType = 'basket';
        }
        
        // Create the new permission request
        const newItem: PermissionItem = {
          requestID,
          protocolSecurityLevel,
          protocolID: protocolNameString,
          counterparty,
          originator,
          description: reason,
          renewal,
          type: permissionType
        }
        
        // Update state in a single batch
        await Promise.all([
          // Request focus if needed
          !wasOriginallyFocused ? onFocusRequested() : Promise.resolve(),
          // Set the original focus state
          new Promise<void>(resolve => {
            setWasOriginallyFocused(wasOriginallyFocused)
            resolve()
          }),
          // Add the new permission request
          new Promise<void>(resolve => {
            setPerms(p => [...p, newItem])
            resolve()
          })
        ])
        
        // Finally, open the dialog
        setOpen(true)
      }
    })
  }, [])

  // Only render if we have both dialog open and permissions to show
  if (!open || perms.length === 0) {
    return null
  }

  // Get the current permission request
  const currentPerm = perms[0]
  console.log({ currentPerm })
  if (!currentPerm) {
    return null
  }

  // Permission type documents
  const permissionTypeDocs = {
    identity: {
      title: 'Trusted Entities Access Request',
      description: 'An app is requesting access to lookup identity information using the entities you trust.',
      icon: <VerifiedUserIcon fontSize="medium" />
    },
    renewal: {
      title: 'Protocol Access Renewal',
      description: 'An app is requesting to renew its previous access to a protocol.',
      icon: <CachedIcon fontSize="medium" />
    },
    basket: {
      title: 'Basket Access Request',
      description: 'An app wants to view your tokens within a specific basket.',
      icon: <ShoppingBasketIcon fontSize="medium" />
    },
    protocol: {
      title: 'Protocol Access Request',
      icon: <CodeIcon fontSize="medium" />
    }
  };

  // Get permission type document
  const getPermissionTypeDoc = () => {
    // Default to protocol if type is undefined
    const type = currentPerm.type || 'protocol';
    return permissionTypeDocs[type];
  };

  const getIconAvatar = () => (
    <Avatar 
      sx={{ 
        width: 40,
        height: 40,
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center'
      }}
    >
      {getPermissionTypeDoc().icon}
    </Avatar>
  );

  return (
    <CustomDialog
      open={open}
      title={getPermissionTypeDoc().title}
      icon={getPermissionTypeDoc().icon}
    >
      <DialogContent>
        {/* Main content with app and protocol details */}
        <Stack spacing={1}>
          {/* App section */}
          {currentPerm.description && <Stack>
            {currentPerm.description}
          </Stack>}

          <AppChip
            size={1.5}
            showDomain
            label={currentPerm.originator || 'unknown'}
            clickable={false}
          />
        
          <Divider />

          <ProtoChip
            size={1.5}
            securityLevel={currentPerm.protocolSecurityLevel}
            protocolID={currentPerm.protocolID}
            counterparty={currentPerm.counterparty}
            description={currentPerm.description}
          />
        </Stack>
      </DialogContent>
      {/* 
        This gradient of colors is just a visual cue to help the user realize that each request is different 
        (sometimes several will pop up one after another and it feels like you're pressing "approve" on the same dialogue over and over again).
      */}
      <Tooltip title="Unique visual signature for this request" placement="top">
        <Box sx={{ mb:3, py: 0.5, background: deterministicColor(JSON.stringify(currentPerm)) }} />
      </Tooltip>

      <DialogActions sx={{ justifyContent: 'space-between' }}>
        <Button 
          onClick={handleCancel}
          variant="outlined"
          color="inherit"
        >
          Deny
        </Button>
        <Button 
          onClick={handleGrant}
          variant="contained"
          color={currentPerm.type === 'identity' ? 'info' : 'primary'}
        >
          Grant Access
        </Button>
      </DialogActions>
    </CustomDialog>
  )
}

export default ProtocolPermissionHandler
