import { useState, useEffect, useContext, useCallback } from 'react'
import { 
  DialogActions, 
  DialogContent, 
  Button, 
  DialogContentText, 
  InputAdornment, 
  IconButton,
  OutlinedInput,
  FormControl,
  InputLabel
} from '@mui/material'
import CustomDialog from './CustomDialog'
import { UserContext, UserContextValue } from '../UserContext'
import { WalletContext, WalletContextValue } from '../WalletContext'
import { Visibility, VisibilityOff } from '@mui/icons-material'
import { toast } from 'react-toastify';

// Type definitions for better type safety
type PasswordTester = (passwordCandidate: string) => boolean;
type PasswordPromiseHandlers = {
  resolve: (value: string) => void;
  reject: () => void;
};

/**
 * PasswordHandler component that manages password retrieval dialogs
 * Refactored to avoid deep nesting and simplify the promise handling
 */
const PasswordHandler: React.FC = () => {
  const {
    onFocusRequested,
    onFocusRelinquished,
    isFocused,
  } = useContext<UserContextValue>(UserContext)
  const { setPasswordRetriever } = useContext<WalletContextValue>(WalletContext)
  
  // Dialog state
  const [open, setOpen] = useState(false)
  const [wasOriginallyFocused, setWasOriginallyFocused] = useState(false)
  const [reason, setReason] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  
  // Password verification state
  const [test, setTest] = useState<PasswordTester>(() => () => false)
  const [promiseHandlers, setPromiseHandlers] = useState<PasswordPromiseHandlers>({
    resolve: () => {},
    reject: () => {}
  })

  // Handle dialog opening with proper focus management
  const openDialog = useCallback(async () => {
    const focused = await isFocused();
    setWasOriginallyFocused(focused);
    
    if (!focused) {
      await onFocusRequested();
    }
    
    setOpen(true);
  }, [isFocused, onFocusRequested]);

  // Handle dialog closing with proper focus management
  const closeDialog = useCallback(async () => {
    setOpen(false);
    setPassword('');
    
    if (!wasOriginallyFocused) {
      await onFocusRelinquished();
    }
  }, [wasOriginallyFocused, onFocusRelinquished]);

  // Create a function that returns a password retriever
  const createPasswordRetriever = useCallback(() => {
    // This is the actual password retriever function that will be used by the wallet
    const passwordRetriever = (reason: string, tester: PasswordTester): Promise<string> => {
      // Create a new promise outside of any nested functions
      let promiseResolve: (value: string) => void;
      let promiseReject: () => void;
      
      const promise = new Promise<string>((resolve, reject) => {
        promiseResolve = resolve;
        promiseReject = reject;
      });
      
      // Store the state needed for password verification
      setReason(reason);
      setTest(() => tester);
      setPromiseHandlers({
        resolve: promiseResolve,
        reject: promiseReject
      });
      
      // Open the dialog (async operation but doesn't affect the promise)
      openDialog();
      
      return promise;
    };
    
    return passwordRetriever;
  }, [openDialog]);

  // Register the password retriever with the wallet context
  useEffect(() => {
    setPasswordRetriever(createPasswordRetriever());
  }, [setPasswordRetriever, createPasswordRetriever]);

  // Handle form submission
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    const success = test(password);
    if (success) {
      promiseHandlers.resolve(password);
      await closeDialog();
    } else {
      toast.error('Incorrect password');
    }
  };

  // Handle abort/cancel
  const handleAbort = async () => {
    promiseHandlers.reject();
    await closeDialog();
  };

  // Toggle password visibility
  const handleTogglePasswordVisibility = () => {
    setShowPassword(!showPassword);
  };

  return (
    <CustomDialog
      open={open}
      title="Password Required"
      backgroundColor="#1a1a1a"
      handleClose={handleAbort}
    >
      <form onSubmit={handleSubmit}>
        <DialogContent>
          <DialogContentText>
            {reason}
          </DialogContentText>
          <FormControl fullWidth variant="outlined" margin="dense">
            <InputLabel htmlFor="password-input">Password</InputLabel>
            <OutlinedInput
              id="password-input"
              type={showPassword ? 'text' : 'password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoFocus
              required
              endAdornment={
                <InputAdornment position="end">
                  <IconButton
                    aria-label="toggle password visibility"
                    onClick={handleTogglePasswordVisibility}
                    edge="end"
                  >
                    {showPassword ? <VisibilityOff /> : <Visibility />}
                  </IconButton>
                </InputAdornment>
              }
              label="Password"
            />
          </FormControl>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleAbort} color="primary">
            Cancel
          </Button>
          <Button type="submit" color="primary">
            Submit
          </Button>
        </DialogActions>
      </form>
    </CustomDialog>
  );
};

export default PasswordHandler;
