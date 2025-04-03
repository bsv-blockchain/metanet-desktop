import { Dispatch, SetStateAction, useState, useEffect, useContext, FC } from 'react'
import { DialogContent, DialogActions, Button, Typography, Divider, Box, Stack, Tooltip } from '@mui/material'
import CustomDialog from '../CustomDialog'
import AppChip from '../AppChip/index'
import BasketChip from '../BasketChip/index'
import { PermissionEventHandler, PermissionRequest } from '@bsv/wallet-toolbox-client'
import { useTheme } from '@mui/material/styles'
import Avatar from '@mui/material/Avatar'
import ShoppingBasketIcon from '@mui/icons-material/ShoppingBasket'
import deterministicColor from '../../utils/deterministicColor'
import { WalletContext } from '../../WalletContext'
import { UserContext } from '../../UserContext'


type BasketAccessRequest = {
    requestID: string
    basket?: string
    originator: string
    reason?: string
    renewal?: boolean
}

const BasketAccessHandler: FC<{
    setBasketAccessHandler: Dispatch<SetStateAction<PermissionEventHandler>>
}> = ({ setBasketAccessHandler }) => {
    const { managers } = useContext(WalletContext)
    const { onFocusRequested, onFocusRelinquished, isFocused } = useContext(UserContext)
    const theme = useTheme()

    // Whether our dialog is open
    const [open, setOpen] = useState(false)

    // Track if we were originally focused
    const [wasOriginallyFocused, setWasOriginallyFocused] = useState(false)

    // This array will queue up multiple requests
    const [requests, setRequests] = useState<BasketAccessRequest[]>([])

    // Provide a handler for basket-access requests that enqueues them
    useEffect(() => {
        setBasketAccessHandler(() => {
            return async (incomingRequest: PermissionRequest & {
                requestID: string
                basket?: string
                originator: string
                reason?: string
                renewal?: boolean
            }) => {
                // Enqueue the new request
                setRequests(prev => {
                    const wasEmpty = prev.length === 0

                    // If no requests were queued, handle focusing logic right away
                    if (wasEmpty) {
                        isFocused().then(currentlyFocused => {
                            setWasOriginallyFocused(currentlyFocused)
                            if (!currentlyFocused) {
                                onFocusRequested()
                            }
                            setOpen(true)
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
        })
    }, [isFocused, onFocusRequested, setBasketAccessHandler])

    // Handle denying the top request in the queue
    const handleDeny = async () => {
        if (requests.length > 0) {
            managers.permissionsManager?.denyPermission(requests[0].requestID)
        }
        advanceQueue()
    }

    // Handle granting the top request in the queue
    const handleGrant = async () => {
        if (requests.length > 0) {
            managers.permissionsManager?.grantPermission({
                requestID: requests[0].requestID
            })
        }
        advanceQueue()
    }

    // Pop the first request from the queue, close if empty, relinquish focus if needed
    const advanceQueue = () => {
        setRequests(prev => {
            const newQueue = prev.slice(1)
            if (newQueue.length === 0) {
                setOpen(false)
                if (!wasOriginallyFocused) {
                    onFocusRelinquished()
                }
            }
            return newQueue
        })
    }

    // If no current request, don't render anything
    if (!requests[0]) {
        return null
    }

    // Current (top) request in the queue
    const { basket, originator, reason, renewal } = requests[0]

    // Get avatar and icon
    const getIconAvatar = () => (
        <Avatar 
            sx={{ 
                bgcolor: theme.approvals?.basket || '#2e7d32',
                width: 40,
                height: 40,
                display: 'flex',
                justifyContent: 'center',
                alignItems: 'center'
            }}
        >
            <ShoppingBasketIcon fontSize="medium" />
        </Avatar>
    );

    return (
        <CustomDialog
            open={open}
            title={renewal ? 'Basket Access Renewal' : 'Basket Access Request'}
            onClose={handleDeny} // If the user closes via the X, treat as "deny"
            icon={<ShoppingBasketIcon fontSize="medium" />}
        >
            <DialogContent>
                <Stack spacing={1}>
                    {/* App section */}
                    <AppChip
                        size={1.5}
                        showDomain
                        label={originator || 'unknown'}
                        clickable={false}
                    />
                    
                    <Divider />

                    {/* Basket section */}
                    <BasketChip basketId={basket} />

                    {/* Reason section */}
                    {reason && (
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
                                        {reason}
                                    </Typography>
                                </Stack>
                            </Stack>
                        </>
                    )}
                </Stack>
            </DialogContent>

            {/* Visual signature */}
            <Tooltip title="Unique visual signature for this request" placement="top">
                <Box sx={{ mb: 3, py: 0.5, background: deterministicColor(JSON.stringify(requests[0])) }} />
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

export default BasketAccessHandler
