import React, { useEffect, useContext } from 'react';
import { useHistory } from 'react-router-dom';
import { WalletContext } from '../WalletContext';

/**
 * Handles auto-login redirect when snapshot has loaded and authentication is valid
 */
const AuthRedirector: React.FC = () => {
    const history = useHistory();
    const { managers } = useContext(WalletContext);

    useEffect(() => {
        if (
            managers.walletManager &&
            (managers.walletManager as any).authenticated
        ) {
            history.push('/dashboard/apps');
        }
    }, [managers.walletManager, history]);

    return null;
};

export default AuthRedirector;
