import { useCallback, useContext } from 'react'
import { DialogContent, DialogActions, Button, Typography, Divider, Box, Stack, Tooltip, useTheme } from '@mui/material'
import CustomDialog from '../CustomDialog'
import AppChip from '../AppChip/index'
import BasketChip from '../BasketChip/index'
import Avatar from '@mui/material/Avatar'
import ShoppingBasketIcon from '@mui/icons-material/ShoppingBasket'
import deterministicColor from '../../utils/deterministicColor'
import { WalletContext } from '../../WalletContext'
import { UserContext } from '../../UserContext'


const BasketAccessHandler = () => {
    const { requests, advanceQueue, managers } = useContext(WalletContext)
    const { basketAccessModalOpen } = useContext(UserContext)
    const theme = useTheme()

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

    if (!basketAccessModalOpen || !requests.length) return null

    const { basket, originator, reason, renewal } = requests[0]

    return (
        <CustomDialog
            open={basketAccessModalOpen}
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
