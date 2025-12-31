// src/components/common/Header.jsx

"use client"
import {
  AppBar,
  Toolbar,
  Typography,
  Button,
  Box,
  Avatar,
  IconButton,
  Badge,
} from "@mui/material"
import { BusinessCenter, Notifications, Settings } from "@mui/icons-material"
import { useAuth } from "../../contexts/AuthContext"
import { useNavigate } from "react-router-dom"

const Header = () => {
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  const handleLogout = () => {
    logout()
    navigate("/login")
  }

  return (
    <AppBar
      position="fixed"
      elevation={0}
      sx={{
        zIndex: (theme) => theme.zIndex.drawer + 1,
        width: "100%",
        backgroundColor: "#ffffff",
        borderBottom: "1px solid rgba(55, 53, 47, 0.09)",
        color: "#37352f",
      }}
    >
      <Toolbar sx={{ minHeight: "68px !important", px: 3 }}>
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
          <BusinessCenter sx={{ fontSize: 28, color: "#37352f" }} />
          <Typography
            variant="h6"
            component="div"
            sx={{
              fontWeight: 600,
              fontSize: "1.125rem",
              color: "#37352f",
              letterSpacing: "-0.005em",
            }}
          >
            회사 포털
          </Typography>
        </Box>

        {user && (
          <Box sx={{ display: "flex", alignItems: "center", gap: 2.5 }}>
            <IconButton
              size="large"
              sx={{
                color: "#787774",
                "&:hover": {
                  backgroundColor: "rgba(55, 53, 47, 0.08)",
                },
              }}
            >
              <Badge badgeContent={3} color="error" sx={{ "& .MuiBadge-badge": { fontSize: "0.75rem" } }}>
                <Notifications sx={{ fontSize: 26 }} />
              </Badge>
            </IconButton>

            <IconButton
              size="large"
              sx={{
                color: "#787774",
                "&:hover": {
                  backgroundColor: "rgba(55, 53, 47, 0.08)",
                },
              }}
            >
              <Settings sx={{ fontSize: 26 }} />
            </IconButton>

            <Box
              sx={{
                display: "flex",
                alignItems: "center",
                gap: 1.5,
                px: 2,
                py: 0.75,
              }}
            >
              <Avatar
                sx={{
                  width: 38,
                  height: 38,
                  bgcolor: "#37352f",
                  fontSize: "1rem",
                  fontWeight: 600,
                }}
              >
                {user.name?.charAt(0) || "U"}
              </Avatar>
              <Box sx={{ minWidth: 70 }}>
                <Typography
                  variant="body2"
                  sx={{
                    fontWeight: 600,
                    lineHeight: 1.3,
                    fontSize: "0.9375rem",
                    color: "#37352f",
                  }}
                >
                  {user.name}
                </Typography>
                <Typography
                  variant="caption"
                  sx={{
                    lineHeight: 1.2,
                    fontSize: "0.8125rem",
                    color: "#787774",
                  }}
                >
                  {user.position}
                </Typography>
              </Box>
            </Box>

            <Button
              onClick={handleLogout}
              sx={{
                px: 2.5,
                py: 1,
                borderRadius: "6px",
                fontSize: "0.9375rem",
                fontWeight: 500,
                color: "#787774",
                border: "1px solid rgba(55, 53, 47, 0.16)",
                "&:hover": {
                  backgroundColor: "rgba(55, 53, 47, 0.08)",
                  borderColor: "rgba(55, 53, 47, 0.24)",
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