import { useState, useContext } from 'react';
import {
  Typography,
  Button,
  LinearProgress,
  useTheme,
  Box,
  Paper
} from '@mui/material';
import Grid from '@mui/material/Grid2'; // Updated to Grid2
import { makeStyles } from '@mui/styles';
import { toast } from 'react-toastify';
import { WalletContext } from "../../UserInterface.js";
import DarkModeImage from "../../images/darkMode.jsx";
import LightModeImage from "../../images/lightMode.jsx";
import { Theme } from '@mui/material/styles';

const useStyles = makeStyles((theme: Theme) => ({
  root: {
    padding: theme.spacing(3),
    maxWidth: '800px',
    margin: '0 auto'
  },
  section: {
    marginBottom: theme.spacing(4)
  },
  themeButton: {
    width: '120px',
    height: '120px',
    borderRadius: theme.shape.borderRadius,
    border: `2px solid ${theme.palette.divider}`,
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    transition: 'all 0.2s ease-in-out',
    '&.selected': {
      borderColor: theme.palette.primary.main,
      borderWidth: '2px',
      boxShadow: theme.shadows[3]
    }
  },
  currencyButton: {
    width: '100px',
    height: '80px',
    margin: '8px',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    transition: 'all 0.2s ease-in-out',
    '&.selected': {
      borderColor: theme.palette.primary.main,
      borderWidth: '2px',
      backgroundColor: theme.palette.action.selected
    }
  }
}));

const Welcome = ({ history }) => {
  const { settings, updateSettings } = useContext(WalletContext);
  const [settingsLoading, setSettingsLoading] = useState(false);
  const theme = useTheme();
  const classes = useStyles();

  // Supported Defaults
  const currencies = {
    BSV: '0.033',
    SATS: '3,333,333',
    USD: '$10',
    EUR: '€9.15',
    GBP: '£7.86'
  };

  const themes = ['light', 'dark'];
  const [selectedTheme, setSelectedTheme] = useState(settings?.theme?.mode || theme.palette.mode);
  const [selectedCurrency, setSelectedCurrency] = useState(settings?.currency || 'BSV');

  // Handle updating defaults
  const handleThemeChange = (theme) => {
    setSelectedTheme(theme.toLowerCase());
  };

  const handleCurrencyChange = (currency) => {
    setSelectedCurrency(currency);
  };

  // Save user preferences
  const showDashboard = async () => {
    try {
      setSettingsLoading(true);
      updateSettings({
        ...settings,
        theme: { mode: selectedTheme },
        currency: selectedCurrency
      });
      history.push('/dashboard/apps');
    } catch (e) {
      toast.error(e.message);
    } finally {
      setSettingsLoading(false);
    }
  };

  return (
    <div className={classes.root}>
      <Typography variant="h1" color="textPrimary" sx={{ mb: 2 }}>
        Your Portal to the Metanet
      </Typography>
      <Typography variant="body1" color="textSecondary" sx={{ mb: 2 }}>
        Let's start by setting your preferences for the best experience.
      </Typography>

      {/* Theme Selection Section */}
      <Paper elevation={0} className={classes.section} sx={{ p: 3, bgcolor: 'background.paper' }}>
        <Typography variant="h4" sx={{ mb: 2 }}>
          Choose Your Theme
        </Typography>
        <Typography variant="body1" color="textSecondary" sx={{ mb: 3 }}>
          Select a theme that's comfortable for your eyes.
        </Typography>

        <Grid container spacing={3} justifyContent="center">
          {themes.map(themeOption => (
            <Grid key={themeOption}>
              <Button
                onClick={() => handleThemeChange(themeOption)}
                className={`${classes.themeButton} ${selectedTheme === themeOption ? 'selected' : ''}`}
                sx={{
                  color: themeOption === 'light' ? 'text.primary' : 'common.white',
                  backgroundColor: themeOption === 'light' ? 'background.default' : 'grey.800',
                }}
              >
                {themeOption === 'light' ? <LightModeImage /> : <DarkModeImage />}
                <Typography variant="body2" sx={{ mt: 1, fontWeight: selectedTheme === themeOption ? 'bold' : 'normal' }}>
                  {themeOption.charAt(0).toUpperCase() + themeOption.slice(1)}
                </Typography>
              </Button>
            </Grid>
          ))}
        </Grid>
      </Paper>

      {/* Currency Selection Section */}
      <Paper elevation={0} className={classes.section} sx={{ p: 3, bgcolor: 'background.paper' }}>
        <Typography variant="h4" sx={{ mb: 2 }}>
          Default Currency
        </Typography>
        <Typography variant="body1" color="textSecondary" sx={{ mb: 3 }}>
          How would you like to see your account balance?
        </Typography>

        <Grid container spacing={2} justifyContent="center">
          {Object.keys(currencies).map(currency => (
            <Grid key={currency}>
              <Button
                variant="outlined"
                className={`${classes.currencyButton} ${selectedCurrency === currency ? 'selected' : ''}`}
                onClick={() => handleCurrencyChange(currency)}
                sx={{
                  borderColor: selectedCurrency === currency ? 'primary.main' : 'divider',
                  bgcolor: selectedCurrency === currency ? 'action.selected' : 'transparent',
                }}
              >
                <Typography variant="body1" fontWeight="bold">
                  {currency}
                </Typography>
                <Typography variant="body2" color="textSecondary">
                  {currencies[currency]}
                </Typography>
              </Button>
            </Grid>
          ))}
        </Grid>
      </Paper>

      {/* Action Button Section */}
      <Box sx={{ display: 'flex', justifyContent: 'center', mt: 4 }}>
        {settingsLoading ? (
          <Box sx={{ width: '200px' }}>
            <LinearProgress />
          </Box>
        ) : (
          <Button
            color="primary"
            variant="contained"
            size="large"
            onClick={showDashboard}
            sx={{ 
              minWidth: '200px', 
              py: 1.5,
              boxShadow: 3,
              '&:hover': {
                boxShadow: 6,
              }
            }}
          >
            View Dashboard
          </Button>
        )}
      </Box>
    </div>
  );
};

export default Welcome;
