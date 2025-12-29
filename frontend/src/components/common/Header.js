import React from 'react';
import { 
  AppBar, 
  Toolbar, 
  Typography, 
  Button, 
  Switch, 
  FormControlLabel,
  Box,
  Chip
} from '@mui/material';
import { useAuth } from '../../contexts/AuthContext';
import { useSecurityMode } from '../../contexts/SecurityModeContext';
import { useNavigate } from 'react-router-dom';

const Header = () => {
  const { user, logout } = useAuth();
  const { securityMode, toggleSecurityMode, isSecure } = useSecurityMode();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <AppBar 
      position="fixed" 
      sx={{ 
        zIndex: (theme) => theme.zIndex.drawer + 1,
        width: '100%'
      }}
    >
      <Toolbar>
        <Typography 
          variant="h6" 
          component="div" 
          sx={{ flexGrow: 1, cursor: 'pointer' }}
          onClick={() => navigate('/dashboard')}
        >
          회사 포털 시스템
        </Typography>

        {user && (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <FormControlLabel
              control={
                <Switch
                  checked={isSecure}
                  onChange={toggleSecurityMode}
                  color="default"
                />
              }
              label={
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Typography>보안 모드:</Typography>
                  <Chip 
                    label={isSecure ? 'ON (보안)' : 'OFF (취약)'} 
                    color={isSecure ? 'success' : 'error'}
                    size="small"
                  />
                </Box>
              }
            />
            
            <Typography variant="body2">
              {user.name} ({user.position})
            </Typography>
            
            <Button color="inherit" onClick={handleLogout}>
              로그아웃
            </Button>
          </Box>
        )}
      </Toolbar>
    </AppBar>
  );
};

export default Header;