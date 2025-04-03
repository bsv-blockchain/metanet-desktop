import { useState, useEffect, useContext } from 'react'
import AmountDisplay from './AmountDisplay'
// import confederacyHost from '../utils/confederacyHost'
import { makeStyles } from '@mui/styles'
import { Typography } from '@mui/material'
import { WalletContext } from '../WalletContext'

const useStyles = makeStyles((theme: any) => ({
  content_wrap: {
    marginTop: '3em',
    zIndex: 3,
    display: 'grid',
    placeItems: 'center',
    paddingBottom: theme.spacing(2)
  },
  manage_link: {
    textDecoration: 'underline'
  }
}), { name: 'Profile' })

const Profile = () => {
  const { managers, adminOriginator } = useContext(WalletContext)
  const [accountBalance, setAccountBalance] = useState<any>(null)
  const [balanceLoading, setBalanceLoading] = useState(true)
  const classes = useStyles()

  const refreshBalance = async () => {
    try {
      setBalanceLoading(true)
      const limit = 10000
      let offset = 0
      let allOutputs = []

      // Fetch the first page
      const firstPage = await managers.permissionsManager.listOutputs({ basket: 'default', limit, offset }, adminOriginator)
      allOutputs = firstPage.outputs;
      const totalOutputs = firstPage.totalOutputs;

      // Fetch subsequent pages until we've retrieved all outputs
      while (allOutputs.length < totalOutputs) {
        offset += limit;
        const { outputs } = await managers.permissionsManager.listOutputs({ basket: 'default', limit, offset }, adminOriginator);
        allOutputs = allOutputs.concat(outputs);
      }

      const total = allOutputs.reduce((acc, output) => acc + output.satoshis, 0)
      setAccountBalance(total)
      setBalanceLoading(false)
    } catch (e) {
      setBalanceLoading(false)
    }
  }

  useEffect(() => {
    (async () => {
      if (typeof adminOriginator === 'string') {
        try {
          refreshBalance()
        } catch (e) { }
      }
    })()
  }, [adminOriginator])

  return (
    <>
      <div className={classes.content_wrap}>
        <Typography variant='h5' color='textSecondary'>
          Your Balance
        </Typography>
        <Typography
          onClick={() => refreshBalance()}
          color='textPrimary'
          variant='h2'
          style={{ cursor: 'pointer' }}
        >
          {balanceLoading
            ? '---'
            : <AmountDisplay abbreviate>{accountBalance}</AmountDisplay>}
        </Typography>
        {/* <a href='#' className={classes.manage_link}>manage</a> */}
      </div>
    </>
  )
}

export default Profile
