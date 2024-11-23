"use client";
import React, { useState, useEffect } from 'react';
import DashboardContent from './DashboardContent';
import AdminLogin from './AdminLogin';

const ClientSideAdminLogin = () => {
    const [authState, setAuthState] = useState('loading');

    useEffect(() => {
        const checkAuth = () => {
            const authToken = document.cookie.includes('auth-token');
            setAuthState(authToken ? 'authenticated' : 'unauthenticated');
        };

        checkAuth();

        // Set up an interval to periodically check authentication
        const authCheckInterval = setInterval(checkAuth, 60000); // Check every minute

        // Clean up the interval on component unmount
        return () => clearInterval(authCheckInterval);
    }, []);

    useEffect(() => {
        // Listen for storage events to sync auth state across tabs
        const handleStorageChange = (e) => {
            if (e.key === 'auth-token') {
                setAuthState(e.newValue ? 'authenticated' : 'unauthenticated');
            }
        };

        window.addEventListener('storage', handleStorageChange);
        return () => window.removeEventListener('storage', handleStorageChange);
    }, []);

    const handleLoginSuccess = () => {
        setAuthState('authenticated');
        // Update localStorage to sync across tabs
        localStorage.setItem('auth-token', 'true');
    };

    const handleLogout = () => {
        document.cookie = "auth-token=; path=/;";
        setAuthState('unauthenticated');
        localStorage.removeItem('auth-token');
    };

    if (typeof window === 'undefined' || authState === 'loading') {
        return <div>
       <div className="flex items-center justify-center min-h-screen">
                <div className="animate-pulse flex flex-col items-center gap-4 w-60">
                    <div>
                        <div className="w-48 h-6 bg-slate-400 rounded-md"></div>
                        <div className="w-28 h-4 bg-slate-400 mx-auto mt-3 rounded-md"></div>
                    </div>
                    <div className="h-7 bg-slate-400 w-full rounded-md"></div>
                    <div className="h-7 bg-slate-400 w-full rounded-md"></div>
                    <div className="h-7 bg-slate-400 w-full rounded-md"></div>
                    <div className="h-7 bg-slate-400 w-1/2 rounded-md"></div>
                </div>
            </div></div>; 
    }

    return (
        <>
            {authState === 'authenticated' ? (
                <DashboardContent onLogout={handleLogout} />
            ) : (
                <AdminLogin onLoginSuccess={handleLoginSuccess} />
            )}
        </>
    );
};

export default ClientSideAdminLogin;