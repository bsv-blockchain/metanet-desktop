import { useState, useEffect, useContext, SetStateAction, FC, Dispatch } from 'react'
import { DialogContent, DialogActions, Button, Typography, Divider, Box, Stack, Tooltip } from '@mui/material'
import CustomDialog from '../CustomDialog/index.jsx'
import AppChip from '../AppChip'
import CertificateChip from '../CertificateChip/index'
import { PermissionEventHandler, PermissionRequest } from '@bsv/wallet-toolbox-client'
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser'
import deterministicColor from '../../utils/deterministicColor'
import { UserContext } from '../../UserContext'
import { WalletContext } from '../../WalletContext'


type CertificateAccessRequest = {
  requestID: string
  certificateType?: string
  fields?: any
  fieldsArray?: string[]
  verifierPublicKey?: string
  originator: string
  description?: string
  renewal?: boolean
}

const CertificateAccessHandler: FC<{
  setCertificateAccessHandler: Dispatch<SetStateAction<PermissionEventHandler>>
}> = ({ setCertificateAccessHandler }) => {
  const { managers } = useContext(WalletContext)
  const { onFocusRequested, onFocusRelinquished, isFocused } = useContext(UserContext)
  const [wasOriginallyFocused, setWasOriginallyFocused] = useState(false)
  const [open, setOpen] = useState(false)
  const [perms, setPerms] = useState<CertificateAccessRequest[]>([])

  const handleGrant = async () => {
    managers.permissionsManager!.grantPermission({
      requestID: perms[0].requestID
    })
    advanceQueue()
  }

  const handleDeny = async () => {
    managers.permissionsManager!.denyPermission(perms[0].requestID)
    advanceQueue()
  }

  // Pop the first request from the queue, close if empty, relinquish focus if needed
  const advanceQueue = () => {
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
    setCertificateAccessHandler((): PermissionEventHandler => {
      return async (args: PermissionRequest & { requestID: string }): Promise<void> => {
        const {
          requestID,
          originator,
          renewal,
          reason
        } = args

        // Extract certificate data, safely handling potentially undefined values
        const certificate = args.certificate as any
        const certType = certificate?.certType || ''
        const fields = certificate?.fields || {}

        // Extract field names as an array for the CertificateChip component
        const fieldsArray = fields ? Object.keys(fields) : []

        const verifier = certificate?.verifier || ''

        // Focus logic
        const currentlyFocused = await isFocused()
        setWasOriginallyFocused(currentlyFocused)
        if (!currentlyFocused) {
          await onFocusRequested()
        }

        // Add to queue
        setPerms(p => {
          const newItem: CertificateAccessRequest = {
            originator,
            verifierPublicKey: verifier,
            certificateType: certType,
            fields,
            fieldsArray,
            renewal,
            requestID,
            description: reason
          }
          return [...p, newItem]
        })

        setOpen(true)
      }
    })
  }, [])

  if (typeof perms[0] === 'undefined') {
    return null
  }

  return (
    <CustomDialog
      open={open}
      onClose={handleDeny}
      title={!perms[0].renewal
        ? 'Certificate Access Request'
        : 'Certificate Access Renewal'
      }
      icon={<VerifiedUserIcon fontSize="medium" />}
    >
      <DialogContent>
        <Stack spacing={1}>
          {/* App section */}
          <AppChip
            size={1.5}
            showDomain
            label={perms[0].originator}
            clickable={false}
          />

          <Divider />

          {/* Certificate section */}
          <CertificateChip
            certType={perms[0].certificateType}
            fieldsToDisplay={perms[0].fieldsArray}
            verifier={perms[0].verifierPublicKey}
          />

          {/* Reason section */}
          {perms[0].description && (
            <>
              <Divider />
              <Stack direction="row" alignItems="center" spacing={1} justifyContent="space-between" sx={{
                height: '3em', width: '100%'
              }}>
                <Typography variant="body1" fontWeight="bold">
                  Reason:
                </Typography>
                <Stack px={3}>
                  <Typography variant="body1">
                    {perms[0].description}
                  </Typography>
                </Stack>
              </Stack>
            </>
          )}
        </Stack>
      </DialogContent>

      {/* Visual signature */}
      <Tooltip title="Unique visual signature for this request" placement="top">
        <Box sx={{ mb: 3, py: 0.5, background: deterministicColor(JSON.stringify(perms[0])) }} />
      </Tooltip>

      <DialogActions sx={{ justifyContent: 'space-between' }}>
        <Button
          onClick={handleDeny}
          variant="outlined"
          color="inherit"
        >
          Deny
        </Button>
        <Button
          onClick={handleGrant}
          variant="contained"
          color="primary"
        >
          Grant Access
        </Button>
      </DialogActions>
    </CustomDialog>
  )
}

export default CertificateAccessHandler
