"use client"
import { AppBar, Toolbar, Typography, Button, Switch, FormControlLabel, Box, Chip, Avatar } from "@mui/material"
import { BusinessCenter, Shield, ShieldOff } from "@mui/icons-material"
import { useAuth } from "../../contexts/AuthContext"
import { useSecurityMode } from "../../contexts/SecurityModeContext"
import { useNavigate } from "react-router-dom"

const Header = () => {
  const { user, logout } = useAuth()
  const { securityMode, toggleSecurityMode, isSecure } = useSecurityMode()
  const navigate = useNavigate()

  const handleLogout = () => {
    logout()
    navigate("/login")
  }

  return (
    <AppBar
      position="fixed"
      sx={{
        zIndex: (theme) => theme.zIndex.drawer + 1,
        width: "100%",
        backgroundColor: "#1e3a5f",
        boxShadow: "0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06)",
      }}
    >
      <Toolbar sx={{ minHeight: "64px !important", px: 3 }}>
        <Box
          sx={{
            display: "flex",
            alignItems: "center",
            gap: 1.5,
            cursor: "pointer",
            flexGrow: 1,
          }}
          onClick={() => navigate("/dashboard")}
        >
          <BusinessCenter sx={{ fontSize: 28 }} />
          <Typography
            variant="h6"
            component="div"
            sx={{
              fontWeight: 700,
              letterSpacing: "-0.01em",
            }}
          >
            회사 포털 시스템
          </Typography>
        </Box>

        {user && (
          <Box sx={{ display: "flex", alignItems: "center", gap: 3 }}>
            <FormControlLabel
              control={
                <Switch
                  checked={isSecure}
                  onChange={toggleSecurityMode}
                  sx={{
                    "& .MuiSwitch-switchBase.Mui-checked": {
                      color: "#10b981",
                    },
                    "& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track": {
                      backgroundColor: "#10b981",
                    },
                  }}
                />
              }
              label={
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  {isSecure ? <Shield sx={{ fontSize: 18 }} /> : <ShieldOff sx={{ fontSize: 18 }} />}
                  <Chip
                    label={isSecure ? "보안 모드" : "취약 모드"}
                    size="small"
                    sx={{
                      backgroundColor: isSecure ? "#10b981" : "#ef4444",
                      color: "white",
                      fontWeight: 600,
                      height: "24px",
                    }}
                  />
                </Box>
              }
              sx={{ margin: 0 }}
            />

            <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
              <Avatar
                sx={{
                  width: 32,
                  height: 32,
                  bgcolor: "#3b7ea1",
                  fontSize: "0.875rem",
                  fontWeight: 600,
                }}
              >
                {user.name?.charAt(0) || "U"}
              </Avatar>
              <Box>
                <Typography variant="body2" sx={{ fontWeight: 600, lineHeight: 1.2 }}>
                  {user.name}
                </Typography>
                <Typography variant="caption" sx={{ lineHeight: 1.2, opacity: 0.9 }}>
                  {user.position}
                </Typography>
              </Box>
            </Box>

            <Button
              color="inherit"
              onClick={handleLogout}
              sx={{
                ml: 1,
                px: 2,
                "&:hover": {
                  backgroundColor: "rgba(255, 255, 255, 0.1)",
                },
              }}
            >
              로그아웃
            </Button>
          </Box>
        )}
      </Toolbar>
    </AppBar>
  )
}

export default Header
