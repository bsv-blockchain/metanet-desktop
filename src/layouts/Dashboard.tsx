import { useState, useEffect, useContext, useRef } from 'react'
import { useBreakpoint } from '../utils/useBreakpoints'
import { Switch, Route, useHistory, Redirect } from 'react-router-dom'
import style from './style.js'
import { makeStyles } from '@mui/styles'
import {
  Typography,
  IconButton,
  Toolbar
} from '@mui/material'
import { WalletContext } from '../WalletContext.js'
import PageLoading from '../components/PageLoading.js'
import Menu from './Menu.js'
import { Menu as MenuIcon, Settings, Apps } from '@mui/icons-material'
import MyIdentity from '../pages/Dashboard/MyIdentity/index.js'
import Trust from '../pages/Dashboard/Trust/index.js'
import App from '../pages/Dashboard/App/index.js'
import Security from '../pages/Dashboard/Security/index.js'

const useStyles = makeStyles(style as any, {
  name: 'Dashboard'
})

/**
 * Renders the Apps page and menu by default
 */
const Dashboard = () => {
  const breakpoints = useBreakpoint()
  const classes = useStyles({ breakpoints })
  const history = useHistory()
  const menuRef = useRef(null)
  const [menuOpen, setMenuOpen] = useState(true)
  const { managers } = useContext(WalletContext)
  const [pageLoading, setPageLoading] = useState(true)
  const [myIdentityKey, setMyIdentityKey] = useState('self')


  const getMargin = () => {
    if (menuOpen && !(breakpoints as any).sm) {
      return '320px'
    }
    return '0px'
  }

  // Check if this is first login and redirect to settings if needed
  useEffect(() => {
    (async () => {
      if (managers.walletManager.authenticated) {
        setPageLoading(false)
        const { publicKey } = await managers.walletManager.getPublicKey({ identityKey: true })
        setMyIdentityKey(publicKey)

        // Check if this is a first-time login
        const isFirstTime = !localStorage.getItem('hasCompletedSetup');
        if (isFirstTime) {
          localStorage.setItem('hasCompletedSetup', 'true');
          // Navigate to settings page for new users
          history.push('/dashboard/settings');
        }
      }
    })()
  }, [managers, history])

  if (pageLoading) {
    return <PageLoading />
  }

  return (
    <div className={classes.content_wrap} style={{ marginLeft: getMargin(), transition: 'margin 0.3s ease' }}>
      <div style={{
        marginLeft: 0,
        width: menuOpen ? `calc(100vw - ${getMargin()})` : '100vw',
        transition: 'width 0.3s ease, margin 0.3s ease'
      }}>
        {(breakpoints as any).sm &&
          <div style={{ padding: '0.5em 0 0 0.5em' }} ref={menuRef}>
            <Toolbar>
              <IconButton
                edge='start'
                onClick={() => setMenuOpen(menuOpen => !menuOpen)}
                aria-label='menu'
                sx={{
                  color: 'primary.main',
                  '&:hover': {
                    backgroundColor: 'rgba(25, 118, 210, 0.1)',
                  }
                }}
              >
                <MenuIcon />
              </IconButton>
            </Toolbar>
          </div>}
      </div>
      <Menu menuOpen={menuOpen} setMenuOpen={setMenuOpen} menuRef={menuRef} />
      <div className={classes.page_container}>
        <Switch>
          <Redirect from='/dashboard/counterparty/self' to={`/dashboard/counterparty/${myIdentityKey}`} />
          <Redirect from='/dashboard/counterparty/anyone' to='/dashboard/counterparty/0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798' />
          <Route
            path='/dashboard/settings'
            component={Settings}
          />
          <Route
            path='/dashboard/identity'
            component={MyIdentity}
          />
          <Route
            path='/dashboard/trust'
            component={Trust}
          />
          <Route
            path='/dashboard/security'
            component={Security}
          />
          <Route
            path='/dashboard/apps'
            component={Apps}
          />
          <Route
            path='/dashboard/app'
            component={App}
          />
          <Route
            component={() => {
              return (
                <div className={classes.full_width} style={{ padding: '1em' }}>
                  <br />
                  <br />
                  <Typography align='center' color='textPrimary'>Use the menu to select a page</Typography>
                </div>
              )
            }}
          />
        </Switch>
      </div>
    </div>
  )
}

export default Dashboard
