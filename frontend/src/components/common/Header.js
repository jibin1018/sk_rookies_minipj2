// src/components/common/Header.jsx

"use client"
import {
  AppBar,
  Toolbar,
  Typography,
  Button,
  Box,
  Avatar,
} from "@mui/material"
import { BusinessCenter } from "@mui/icons-material"
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
        {/* 로고 영역 */}
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
            sx={{
              fontWeight: 600,
              fontSize: "1.125rem",
              letterSpacing: "-0.005em",
            }}
          >
            회사 포털
          </Typography>
        </Box>

        {/* 사용자 영역 */}
        {user && (
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
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
                    fontSize: "0.9375rem",
                    lineHeight: 1.3,
                  }}
                >
                  {user.name}
                </Typography>
                <Typography
                  variant="caption"
                  sx={{
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
