import { Dispatch, SetStateAction, useState, useEffect, useContext } from 'react'
import {
  DialogContent,
  Typography,
  Fab,
  Tooltip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper
} from '@mui/material'
import makeStyles from '@mui/styles/makeStyles'
import style from './style.js'
import AmountDisplay from '../AmountDisplay/index.js'
import { Send, Cancel } from '@mui/icons-material'
import CustomDialog from '../CustomDialog/index.js'
import { WalletContext } from '../../WalletContext.js'
import AppChip from '../AppChip/index.js'
import { PermissionEventHandler, PermissionRequest, Services } from '@bsv/wallet-toolbox-client'
import { UserContext } from '../../UserContext.js'

const services = new Services('main')

const useStyles = makeStyles(style, {
  name: 'SpendingAuthorizationHandler'
})

const SpendingAuthorizationHandler: React.FC<{
  setSpendingAuthorizationCallback: Dispatch<SetStateAction<PermissionEventHandler>>
}> = ({ setSpendingAuthorizationCallback }) => {
  const {
    managers
  } = useContext(WalletContext)
  const {
    onFocusRequested,
    onFocusRelinquished,
    isFocused
  } = useContext(UserContext)
  const [usdPerBsv, setUsdPerBSV] = useState(35)
  const [wasOriginallyFocused, setWasOriginallyFocused] = useState(false)
  const [open, setOpen] = useState(false)
  const [perms, setPerms] = useState<Array<any>>([
    // originator
    // requestID
    // lineItems
    // renewal
    // transactionAmount
    // amountPreviouslyAuthorized
  ])
  const classes = useStyles()

  // Helper function to figure out the upgrade amount (note: consider moving to utils)
  const determineUpgradeAmount = (previousAmountInSats: any, returnType = 'sats') => {
    let usdAmount
    const previousAmountInUsd = previousAmountInSats * (usdPerBsv / 100000000)

    // The supported spending limits are $5, $10, $20, $50
    if (previousAmountInUsd <= 5) {
      usdAmount = 5
    } else if (previousAmountInUsd <= 10) {
      usdAmount = 10
    } else if (previousAmountInUsd <= 20) {
      usdAmount = 20
    } else {
      usdAmount = 50
    }

    if (returnType === 'sats') {
      return Math.round(usdAmount / (usdPerBsv / 100000000))
    }
    return usdAmount
  }

  const handleCancel = () => {
    managers.permissionsManager!.denyPermission(perms[0].requestID)
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

  const handleGrant = async ({ singular = true, amount }: { singular?: boolean, amount?: number }) => {
    managers.permissionsManager!.grantPermission({
      requestID: perms[0].requestID,
      ephemeral: singular,
      amount
    })
    setPerms(prev => {
      const newPerms = prev.slice(1)  // copy all but the first element
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
    setSpendingAuthorizationCallback(() => {
      return async (args: PermissionRequest & { requestID: string }): Promise<void> => {
        const {
          requestID,
          originator,
          reason,
          renewal,
          spending
        } = args
        let {
          satoshis,
          lineItems
        } = spending!
        if (!lineItems) {
          lineItems = []
        }

        // TODO: support these
        const transactionAmount = 0
        const totalPastSpending = 0
        const amountPreviouslyAuthorized = 0

        setOpen(true)
        const wasOriginallyFocused = await isFocused()
        if (!wasOriginallyFocused) {
          await onFocusRequested()
        }
        if (perms.length === 0) {
          setWasOriginallyFocused(wasOriginallyFocused)
        }
        setPerms(p => {
          const newItem = {
            requestID,
            originator,
            description: reason,
            transactionAmount,
            totalPastSpending,
            amountPreviouslyAuthorized,
            authorizationAmount: satoshis,
            renewal,
            lineItems
          }
          return [...p, newItem]
        })
        const rate = await services.getBsvExchangeRate()
        setUsdPerBSV(rate)
      }
    })
  }, [])

  if (typeof perms[0] === 'undefined') {
    return null
  }

  return (
    <CustomDialog
      open={open}
      title={!perms[0].renewal ? 'Spending Request' : 'Spending Check-in'}
    >
      <DialogContent>
        <br />
        <center>
          <AppChip
            size={2.5}
            label={perms[0].originator}
            clickable={false}
            showDomain
          />
          <br />
          <br />
        </center>
        <Typography align='center'>
          would like to spend
        </Typography>
        <Typography variant='h3' align='center' paragraph color='textPrimary'>
          <AmountDisplay >{perms[0].transactionAmount}</AmountDisplay>
        </Typography>

        <Typography align='center'>
          <TableContainer component={Paper}>
            <Table sx={{ minWidth: 250 }} aria-label='simple table' size='small'>
              <TableHead>
                <TableRow
                  sx={{
                    borderBottom: '2px solid black',
                    '& th': {
                      fontSize: '14px',
                      fontWeight: 'bold'
                    }
                  }}
                >
                  <TableCell>Description</TableCell>
                  <TableCell align='right'>Amount</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {perms[0].lineItems.map((row: any) => (
                  <TableRow
                    key={row.description}
                    sx={{ '&:last-child td, &:last-child th': { border: 0 } }}
                  >
                    <TableCell component='th' scope='row'>
                      {row.description}
                    </TableCell>
                    <TableCell align='right'> <AmountDisplay showPlus abbreviate>{row.satoshis}</AmountDisplay></TableCell>
                  </TableRow>
                ))}
                <TableRow
                  sx={{ '&:last-child td, &:last-child th': { border: 0, fontWeight: 'bold' } }}
                >
                  <TableCell component='th' scope='row'>
                    <b>Total</b>
                  </TableCell>
                  <TableCell align='right'><AmountDisplay showPlus abbreviate>{perms[0].transactionAmount * -1}</AmountDisplay></TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </TableContainer>
        </Typography>

        <div className={classes.fabs_wrap}>
          <Tooltip title='Deny Permission'>
            <Fab
              color='secondary'
              onClick={handleCancel}
              variant='extended'
            >
              <Cancel className={classes.button_icon} />
              Deny
            </Fab>
          </Tooltip>
          <Fab
            variant='extended'
            onClick={() => handleGrant({ singular: false, amount: determineUpgradeAmount(perms[0].amountPreviouslyAuthorized) })}
          >
            Allow up to &nbsp;<AmountDisplay showFiatAsInteger>{determineUpgradeAmount(perms[0].amountPreviouslyAuthorized)}</AmountDisplay>
          </Fab>
          <Tooltip title='Allow Once'>
            <Fab
              color='primary'
              onClick={() => handleGrant({ singular: true })}
              variant='extended'
            >
              <Send className={classes.button_icon} />
              Allow
            </Fab>
          </Tooltip>
        </div>
      </DialogContent>
    </CustomDialog>
  )
}

export default SpendingAuthorizationHandler
