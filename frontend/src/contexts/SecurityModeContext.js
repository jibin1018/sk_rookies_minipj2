import React, { createContext, useState, useContext, useEffect } from 'react';

const SecurityModeContext = createContext(null);

export const SecurityModeProvider = ({ children }) => {
  const [securityMode, setSecurityMode] = useState('secure');

  useEffect(() => {
    const savedMode = localStorage.getItem('securityMode') || 'secure';
    setSecurityMode(savedMode);
  }, []);

  const toggleSecurityMode = () => {
    const newMode = securityMode === 'secure' ? 'vulnerable' : 'secure';
    setSecurityMode(newMode);
    localStorage.setItem('securityMode', newMode);
  };

  const value = {
    securityMode,
    toggleSecurityMode,
    isSecure: securityMode === 'secure',
  };

  return (
    <SecurityModeContext.Provider value={value}>
      {children}
    </SecurityModeContext.Provider>
  );
};

export const useSecurityMode = () => {
  const context = useContext(SecurityModeContext);
  if (!context) {
    throw new Error('useSecurityMode must be used within SecurityModeProvider');
  }
  return context;
};