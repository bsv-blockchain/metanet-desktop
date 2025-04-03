import { useContext, useState, useEffect, useRef } from 'react'
import { open } from '@tauri-apps/plugin-shell'
import style from './style'
import {
  Typography,
  Button,
  TextField,
  CircularProgress,
  Divider,
  InputAdornment,
  IconButton,
  Paper,
  Box,
  Container,
  useTheme,
  Collapse,
  Stepper,
  Step,
  StepLabel,
  StepContent
} from '@mui/material'
import {
  SettingsPhone as PhoneIcon,
  CheckCircle as CheckCircleIcon,
  PermPhoneMsg as SMSIcon,
  Lock as LockIcon,
  Settings as SettingsIcon,
  Restore as RestoreIcon,
  Visibility,
  VisibilityOff
} from '@mui/icons-material'
import PhoneEntry from '../../components/PhoneEntry.js'
import AppLogo from '../../components/AppLogo'
import { toast } from 'react-toastify'
import { WalletContext } from '../../WalletContext'
import { UserContext } from '../../UserContext'
import PageLoading from '../../components/PageLoading.js'
import { Utils } from '@bsv/sdk'
import { makeStyles } from '@mui/styles'
import { Link as RouterLink } from 'react-router-dom'
import { DEFAULT_CHAIN, DEFAULT_WAB_URL, DEFAULT_STORAGE_URL } from '../../config.js'

const useStyles = makeStyles(style as any, { name: 'Greeter' })

// Helper functions for the Stepper
const viewToStepIndex = {
  'phone': 0,
  'code': 1,
  'password': 2
};

// Steps for the stepper
const steps = [
  {
    label: 'Phone Number',
    icon: <PhoneIcon />,
    description: 'Enter your phone number for verification',
  },
  {
    label: 'Verification Code',
    icon: <SMSIcon />,
    description: 'Enter the code you received via SMS',
  },
  {
    label: 'Password',
    icon: <LockIcon />,
    description: 'Enter your password',
  },
];

// Phone form component to reduce cognitive complexity
const PhoneForm = ({ phone, setPhone, loading, handleSubmitPhone, phoneFieldRef }) => {
  const theme = useTheme();
  return (
    <form onSubmit={handleSubmitPhone}>
      <PhoneEntry
        value={phone}
        onChange={setPhone}
        ref={phoneFieldRef}
        sx={{
          width: '100%',
          mb: 2
        }}
      />
      <Button
        variant='contained'
        type='submit'
        disabled={loading || !phone || phone.length < 10}
        fullWidth
        sx={{ 
          mt: 2,
          borderRadius: theme.shape.borderRadius,
          textTransform: 'none',
          py: 1.2
        }}
      >
        {loading ? <CircularProgress size={24} /> : 'Continue'}
      </Button>
    </form>
  );
};

// Code verification form component
const CodeForm = ({ code, setCode, loading, handleSubmitCode, handleResendCode, codeFieldRef }) => {
  const theme = useTheme();
  return (
    <>
      <form onSubmit={handleSubmitCode}>
        <TextField
          label="6-digit code"
          onChange={(e) => setCode(e.target.value)}
          variant="outlined"
          fullWidth
          disabled={loading}
          slotProps={{
            input: {
              ref: codeFieldRef,
              endAdornment: (
                <InputAdornment position="end">
                  {code.length === 6 && <CheckCircleIcon color='success' />}
                </InputAdornment>
              ),
            }
          }}
          sx={{ 
            mb: 2   
          }}
        />
        <Button
          variant='contained'
          type='submit'
          disabled={loading || code.length !== 6}
          fullWidth
          sx={{ 
            mt: 2,
            borderRadius: theme.shape.borderRadius,
            textTransform: 'none',
            py: 1.2
          }}
        >
          {loading ? <CircularProgress size={24} /> : 'Verify Code'}
        </Button>
      </form>
      <Box sx={{ display: 'flex', justifyContent: 'center', mt: 2 }}>
        <Button
          disabled={loading}
          onClick={handleResendCode}
          size="small"
          color="secondary"
          sx={{ textTransform: 'none' }}
        >
          Resend Code
        </Button>
      </Box>
    </>
  );
};

// Password form component
const PasswordForm = ({ password, setPassword, confirmPassword, setConfirmPassword, showPassword, setShowPassword, loading, handleSubmitPassword, accountStatus, passwordFieldRef }) => {
  return (
    <form onSubmit={handleSubmitPassword}>
      <TextField
        label="Password"
        onChange={(e) => setPassword(e.target.value)}
        type={showPassword ? 'text' : 'password'}
        variant="outlined"
        fullWidth
        disabled={loading}
        slotProps={{
          input: {
            ref: passwordFieldRef,
            endAdornment: (
              <InputAdornment position="end">
                <IconButton
                  aria-label="toggle password visibility"
                  onClick={() => setShowPassword(!showPassword)}
                  edge="end"
                >
                  {showPassword ? <VisibilityOff /> : <Visibility />}
                </IconButton>
              </InputAdornment>
            ),
          }
        }}
        sx={{ 
          mb: 2
        }}
      />

      {accountStatus === 'new-user' && (
        <TextField
          label="Confirm Password"
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
          type={showPassword ? 'text' : 'password'}
          variant="outlined"
          fullWidth
          disabled={loading}
          slotProps={{
            input: {
              endAdornment: (
                <InputAdornment position="end">
                  <IconButton
                    aria-label="toggle password visibility"
                    onClick={() => setShowPassword(!showPassword)}
                    edge="end"
                  >
                    {showPassword ? <VisibilityOff /> : <Visibility />}
                  </IconButton>
                </InputAdornment>
              ),
            }
          }}
          sx={{ 
            mb: 2
          }}
        />
      )}

      <Button
        variant='contained'
        type='submit'
        disabled={loading || !password || (accountStatus === 'new-user' && !confirmPassword)}
        fullWidth
        sx={{ 
          mt: 2,
          textTransform: 'none',
          py: 1.2
        }}
      >
        {loading ? <CircularProgress size={24} /> : (accountStatus === 'new-user' ? 'Create Account' : 'Login')}
      </Button>
    </form>
  );
};

// Main Greeter component with reduced complexity
const Greeter: React.FC<any> = ({ history }) => {
  const { managers, snapshotLoaded } = useContext(WalletContext)
  const { appVersion, appName } = useContext(UserContext)
  const theme = useTheme()

  // We keep the same Accordion steps: phone, code, password
  const [step, setStep] = useState('phone')
  const [phone, setPhone] = useState('')
  const [code, setCode] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [accountStatus, setAccountStatus] = useState<string | undefined>(undefined)
  const [loading, setLoading] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [pageLoaded, setPageLoaded] = useState(false)
  
  // Wallet configuration state
  const [showWalletConfig, setShowWalletConfig] = useState(false)
  const [wabUrl, setWabUrl] = useState<string>(DEFAULT_WAB_URL)
  const [wabInfo, setWabInfo] = useState<{
    supportedAuthMethods: string[];
    faucetEnabled: boolean;
    faucetAmount: number;
  } | null>(null)
  const [selectedAuthMethod, setSelectedAuthMethod] = useState<string>("")
  const [selectedNetwork, setSelectedNetwork] = useState<'main' | 'test'>(DEFAULT_CHAIN)
  const [selectedStorageUrl, setSelectedStorageUrl] = useState<string>(DEFAULT_STORAGE_URL)
  const [isLoadingConfig, setIsLoadingConfig] = useState(false)

  const phoneFieldRef = useRef(null)
  const codeFieldRef = useRef(null)
  const passwordFieldRef = useRef(null)

  // Access the manager:
  const walletManager = managers.walletManager

  // Auto-fetch wallet configuration info when component mounts
  useEffect(() => {
    if (!wabInfo && !walletManager?.authenticated) {
      fetchWalletConfig()
    }
  }, [])

  // Fetch wallet configuration info
  const fetchWalletConfig = async () => {
    setIsLoadingConfig(true)
    try {
      console.log({ wabUrl, wabInfo })
      const res = await fetch(`${wabUrl}/info`)
      if (!res.ok) {
        throw new Error(`Failed to fetch info: ${res.status}`)
      }
      const info = await res.json()
      setWabInfo(info)
      
      // Auto-select the first supported authentication method
      if (info.supportedAuthMethods && info.supportedAuthMethods.length > 0) {
        setSelectedAuthMethod(info.supportedAuthMethods[0])
      }
    } catch (error: any) {
      console.error("Error fetching wallet config:", error)
      toast.error("Could not fetch wallet configuration: " + error.message)
    } finally {
      setIsLoadingConfig(false)
    }
  }

  // Apply wallet configuration
  const applyWalletConfig = () => {
    if (!wabInfo || !selectedAuthMethod) {
      toast.error("Please select an authentication method")
      return
    }
    setShowWalletConfig(false)
    fetchWalletConfig().then(() => toast.success("Wallet configuration applied"))
  }

  useEffect(() => {
        if (
            managers?.walletManager?.authenticated && snapshotLoaded
        ) {
            history.push('/dashboard/apps')
            setPageLoaded(true)
        }
    }, [managers?.walletManager?.authenticated, snapshotLoaded, history])

  // Force the manager to use the "presentation-key-and-password" flow:
  useEffect(() => {
    if (walletManager) {
      walletManager.authenticationMode = 'presentation-key-and-password'
    }
  }, [walletManager])

  // Step 1: The user enters a phone number, we call manager.startAuth(...)
  const handleSubmitPhone = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!walletManager) {
      toast.error("Wallet Manager not ready yet.")
      return
    }
    try {
      setLoading(true)
      await walletManager.startAuth({ phoneNumber: phone })
      setStep('code')
      toast.success('A code has been sent to your phone.')
      // Move focus to code field
      if (codeFieldRef.current) {
        codeFieldRef.current.focus()
      }
    } catch (err: any) {
      console.error(err)
      toast.error(err.message || "Failed to send code")
    } finally {
      setLoading(false)
    }
  }

  // Step 2: The user enters the OTP code, we call manager.completeAuth(...)
  const handleSubmitCode = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!walletManager) {
      toast.error("Wallet Manager not ready yet.")
      return
    }
    try {
      setLoading(true)
      await walletManager.completeAuth({ phoneNumber: phone, otp: code })

      if (walletManager.authenticationFlow === 'new-user') {
        setAccountStatus('new-user')
      } else {
        setAccountStatus('existing-user')
      }

      setStep('password')
      if (passwordFieldRef.current) {
        passwordFieldRef.current.focus()
      }
    } catch (err: any) {
      console.error(err)
      toast.error(err.message || "Failed to verify code")
    } finally {
      setLoading(false)
    }
  }

  // Optional "resend code" that just calls startAuth again
  const handleResendCode = async () => {
    if (!walletManager) return
    try {
      setLoading(true)
      await walletManager.startAuth({ phoneNumber: phone })
      toast.success('A new code has been sent to your phone.')
    } catch (e: any) {
      console.error(e)
      toast.error(e.message)
    } finally {
      // small delay to avoid spam
      await new Promise(resolve => setTimeout(resolve, 2000))
      setLoading(false)
    }
  }

  // Step 3: Provide a password for the final step.
  const handleSubmitPassword = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!walletManager) {
      toast.error("Wallet Manager not ready yet.")
      return
    }

    // If new-user, confirm password match
    if (accountStatus === 'new-user' && password !== confirmPassword) {
      toast.error("Passwords don't match.")
      return
    }

    setLoading(true)
    try {
      await walletManager.providePassword(password)

      if (walletManager.authenticated) {
        // Save snapshot to local storage
        localStorage.snap = Utils.toBase64(walletManager.saveSnapshot())
        toast.success("Authenticated successfully!")
        history.push('/dashboard/apps')
      } else {
        throw new Error('Authentication failed, maybe password is incorrect?')
      }
    } catch (err: any) {
      console.error(err)
      toast.error(err.message)
    } finally {
      setLoading(false)
    }
  }

  if (!pageLoaded) {
    return <PageLoading />
  }

  return (
    <Container maxWidth="sm" sx={{ height: '100vh', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
      <Paper 
        elevation={4} 
        sx={{ 
          p: 4, 
          borderRadius: 2,
          bgcolor: 'background.paper',
          boxShadow: theme.shadows[3]
        }}
      >
        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', mb: 4 }}>
          <Box sx={{ mb: 2, width: '100px', height: '100px' }}>
            <AppLogo
              rotate
              size="100px"
              color="#2196F3"
            />
          </Box>
          <Typography 
            variant='h2' 
            fontFamily='Helvetica' 
            fontSize='2em'
            sx={{
              mb: 1,
              fontWeight: 'bold',
              background: theme.palette.mode === 'dark' 
                ? 'linear-gradient(90deg, #FFFFFF 0%, #F5F5F5 100%)'
                : 'linear-gradient(90deg, #2196F3 0%, #4569E5 100%)',
              backgroundClip: 'text',
              WebkitTextFillColor: 'transparent'
            }}
          >
            {appName}
          </Typography>
          <Typography 
            variant="body1"
            color="text.secondary"
            align="center"
            sx={{ mb: 3 }}
          >
            Secure BSV Blockchain Wallet
          </Typography>
          <Divider sx={{ width: '80%' }} />
          <Typography 
            variant="caption"
            color="text.secondary"
            align="center"
            sx={{ mt: 1 }}
          >
            <i>v{appVersion}</i>
          </Typography>
        </Box>

        {/* Wallet Configuration Card */}
        <Box sx={{ mb: 3 }}>
          <Box>
            <Box sx={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'center' }}>
              <Button 
                startIcon={<SettingsIcon />}
                onClick={() => setShowWalletConfig(!showWalletConfig)}
                variant="text"
                color='secondary'
                size="small"
              >
                {showWalletConfig ? 'Hide Details' : 'Show Config'}
              </Button>
            </Box>            
            {isLoadingConfig ? (
              <Box sx={{ display: 'flex', justifyContent: 'center', py: 2 }}>
                <CircularProgress size={24} />
              </Box>
            ) : (
              <>
                {wabInfo ? (            
                  <Collapse in={showWalletConfig}>
                    <Typography variant="h4" color="primary">
                      Configuration
                    </Typography>
                    <Box sx={{ py: 2 }}>
                      <Typography variant="body2" gutterBottom>
                        Wallet Authentication Backend (WAB) provides 2 of 3 backup and recovery functionality for your root key.
                      </Typography>
                      <TextField
                        label="WAB URL"
                        fullWidth
                        variant="outlined"
                        value={wabUrl}
                        onChange={(e) => setWabUrl(e.target.value)}
                        margin="normal"
                        size="small"
                      />
                      <Box sx={{ display: 'flex', justifyContent: 'flex-end', mb: 2 }}>
                        <Button 
                          variant="outlined" 
                          size="small" 
                          onClick={fetchWalletConfig}
                          disabled={isLoadingConfig}
                        >
                          Refresh Info
                        </Button>
                      </Box>
                      <Divider />
                      {wabInfo.supportedAuthMethods && wabInfo.supportedAuthMethods.length > 0 && (
                        <Box sx={{ mt: 2 }}>
                          <Typography variant="body2" gutterBottom>
                            Service which will be used to verify your phone number:
                          </Typography>
                          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                            {wabInfo.supportedAuthMethods.map((method) => (
                              <Button
                                key={method}
                                variant={selectedAuthMethod === method ? "contained" : "outlined"}
                                size="small"
                                onClick={() => setSelectedAuthMethod(method)}
                                sx={{ textTransform: 'none' }}
                              >
                                {method}
                              </Button>
                            ))}
                          </Box>
                        </Box>
                      )}
                      
                      <Box sx={{ mt: 2 }}>
                        <Typography variant="body2" gutterBottom>
                          BSV Network:
                        </Typography>
                        <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
                          <Button
                            variant={selectedNetwork === 'main' ? "contained" : "outlined"}
                            size="small"
                            onClick={() => setSelectedNetwork('main')}
                            sx={{ textTransform: 'none' }}
                          >
                            Mainnet
                          </Button>
                          <Button
                            variant={selectedNetwork === 'test' ? "contained" : "outlined"}
                            size="small"
                            onClick={() => setSelectedNetwork('test')}
                            sx={{ textTransform: 'none' }}
                          >
                            Testnet
                          </Button>
                        </Box>
                      </Box>
                      
                      <Typography variant="body2" gutterBottom>
                        Wallet Storage Provider to use for your transactions and metadata:
                      </Typography>
                      <TextField
                        label="Storage URL"
                        fullWidth
                        variant="outlined"
                        value={selectedStorageUrl}
                        onChange={(e) => setSelectedStorageUrl(e.target.value)}
                        margin="normal"
                        size="small"
                      />
                    </Box>
                    <Box sx={{ display: 'flex', justifyContent: 'flex-end', mt: 2 }}>
                        <Button
                          variant="contained"
                          size="small"
                          color="primary"
                          onClick={applyWalletConfig}
                          disabled={!wabInfo || !selectedAuthMethod}
                        >
                          Apply Configuration
                        </Button>
                    </Box>
                  </Collapse>
                ) : (
                  <Typography variant="body2" color="error">
                    Failed to load wallet configuration
                  </Typography>
                )}
              </>
            )}
          </Box>
        </Box>

        {/* Authentication Stepper - replaces Accordions for clearer progression */}
        <Stepper activeStep={viewToStepIndex[step]} orientation="vertical">
          {steps.map((step, index) => (
            <Step key={step.label}>
              <StepLabel 
                icon={step.icon}
                optional={
                  <Typography variant="caption" color="text.secondary">
                    {step.description}
                  </Typography>
                }
              >
                <Typography variant="body2" fontWeight={500}>
                  {step.label}
                </Typography>
              </StepLabel>
              <StepContent>
                {index === 0 && (
                  <PhoneForm 
                    phone={phone}
                    setPhone={setPhone}
                    loading={loading}
                    handleSubmitPhone={handleSubmitPhone}
                    phoneFieldRef={phoneFieldRef}
                  />
                )}
                
                {index === 1 && (
                  <CodeForm
                    code={code}
                    setCode={setCode}
                    loading={loading}
                    handleSubmitCode={handleSubmitCode}
                    handleResendCode={handleResendCode}
                    codeFieldRef={codeFieldRef}
                  />
                )}
                
                {index === 2 && (
                  <PasswordForm 
                    password={password}
                    setPassword={setPassword}
                    confirmPassword={confirmPassword}
                    setConfirmPassword={setConfirmPassword}
                    showPassword={showPassword}
                    setShowPassword={setShowPassword}
                    loading={loading}
                    handleSubmitPassword={handleSubmitPassword}
                    accountStatus={accountStatus}
                    passwordFieldRef={passwordFieldRef}
                  />
                )}
              </StepContent>
            </Step>
          ))}
        </Stepper>

        <Box sx={{ display: 'flex', justifyContent: 'center', mt: 4, mb: 2 }}>
          <RouterLink to='/recovery' style={{ textDecoration: 'none' }}>
            <Button 
              variant="text" 
              color='secondary'
              size="small"
              startIcon={<RestoreIcon />}
            >
              Account Recovery
            </Button>
          </RouterLink>
        </Box>

        <Typography
          variant='caption'
          color='textSecondary'
          align='center'
          sx={{ 
            display: 'block',
            mt: 3,
            mb: 1,
            fontSize: '0.75rem',
            opacity: 0.7
          }}
        >
          By using this software, you acknowledge that you have read, understood and accepted the terms of the{' '}
          <a
            href='https://github.com/bitcoin-sv/metanet-desktop/blob/master/LICENSE.txt'
            target='_blank'
            rel='noopener noreferrer'
            onClick={async e => {
              e.preventDefault()
              await open('https://github.com/bitcoin-sv/metanet-desktop/blob/master/LICENSE.txt')
            }}
            style={{ color: theme.palette.primary.main, textDecoration: 'none' }}
          >
            Software License
          </a>.
        </Typography>
      </Paper>
    </Container>
  )
}

export default Greeter
