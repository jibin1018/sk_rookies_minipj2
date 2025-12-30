"use client"

import { useState } from "react"
import { Container, Box, TextField, Button, Typography, Paper, Alert, CircularProgress, Divider } from "@mui/material"
import { BusinessCenter, Lock, Person } from "@mui/icons-material"
import { useAuth } from "../../contexts/AuthContext"
import { useNavigate } from "react-router-dom"

const LoginPage = () => {
  const [employeeId, setEmployeeId] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)

  const { login } = useAuth()
  const navigate = useNavigate()

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError("")
    setLoading(true)

    console.log("로그인 시도:", employeeId)

    try {
      const result = await login(employeeId, password)
      console.log("로그인 결과:", result)

      if (result.success) {
        console.log("로그인 성공, 대시보드로 이동")
        navigate("/dashboard")
      } else {
        console.log("로그인 실패:", result.message)
        setError(result.message || "로그인에 실패했습니다")
      }
    } catch (err) {
      console.error("로그인 에러:", err)
      setError("로그인 중 오류가 발생했습니다")
    } finally {
      setLoading(false)
    }
  }

  return (
    <Box
      sx={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "linear-gradient(135deg, #1e3a5f 0%, #2d5278 50%, #3b7ea1 100%)",
      }}
    >
      <Container maxWidth="sm">
        <Box
          sx={{
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
          }}
        >
          <Paper
            elevation={3}
            sx={{
              padding: 5,
              width: "100%",
              borderRadius: 3,
              boxShadow: "0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)",
            }}
          >
            <Box sx={{ display: "flex", justifyContent: "center", mb: 3 }}>
              <Box
                sx={{
                  p: 2,
                  borderRadius: 2,
                  backgroundColor: "#eff6ff",
                  color: "#1e3a5f",
                }}
              >
                <BusinessCenter sx={{ fontSize: 48 }} />
              </Box>
            </Box>

            <Typography
              component="h1"
              variant="h4"
              align="center"
              gutterBottom
              sx={{ fontWeight: 700, color: "#1e3a5f", mb: 1 }}
            >
              회사 포털 시스템
            </Typography>

            <Typography variant="body1" align="center" color="text.secondary" sx={{ mb: 4 }}>
              로그인하여 시스템을 이용하세요
            </Typography>

            {error && (
              <Alert severity="error" sx={{ mb: 3, borderRadius: 2 }}>
                {error}
              </Alert>
            )}

            <Box component="form" onSubmit={handleSubmit}>
              <TextField
                margin="normal"
                required
                fullWidth
                label="사번"
                autoComplete="username"
                autoFocus
                value={employeeId}
                onChange={(e) => setEmployeeId(e.target.value)}
                disabled={loading}
                InputProps={{
                  startAdornment: <Person sx={{ color: "action.active", mr: 1 }} />,
                }}
                sx={{ mb: 2 }}
              />

              <TextField
                margin="normal"
                required
                fullWidth
                label="비밀번호"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={loading}
                InputProps={{
                  startAdornment: <Lock sx={{ color: "action.active", mr: 1 }} />,
                }}
                sx={{ mb: 3 }}
              />

              <Button
                type="submit"
                fullWidth
                variant="contained"
                size="large"
                disabled={loading}
                sx={{
                  py: 1.5,
                  mb: 3,
                  fontSize: "1rem",
                  fontWeight: 600,
                }}
              >
                {loading ? <CircularProgress size={24} color="inherit" /> : "로그인"}
              </Button>

              <Divider sx={{ my: 3 }} />

              <Box sx={{ p: 3, bgcolor: "#f9fafb", borderRadius: 2 }}>
                <Typography variant="subtitle2" gutterBottom sx={{ fontWeight: 600, mb: 2 }}>
                  테스트 계정
                </Typography>
                <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                  <Box sx={{ display: "flex", justifyContent: "space-between" }}>
                    <Typography variant="body2" color="text.secondary">
                      관리자:
                    </Typography>
                    <Typography variant="body2" sx={{ fontWeight: 500 }}>
                      admin / admin123
                    </Typography>
                  </Box>
                  <Box sx={{ display: "flex", justifyContent: "space-between" }}>
                    <Typography variant="body2" color="text.secondary">
                      일반사원:
                    </Typography>
                    <Typography variant="body2" sx={{ fontWeight: 500 }}>
                      EMP001 / admin123
                    </Typography>
                  </Box>
                  <Box sx={{ display: "flex", justifyContent: "space-between" }}>
                    <Typography variant="body2" color="text.secondary">
                      팀장:
                    </Typography>
                    <Typography variant="body2" sx={{ fontWeight: 500 }}>
                      EMP002 / admin123
                    </Typography>
                  </Box>
                </Box>
              </Box>
            </Box>
          </Paper>
        </Box>
      </Container>
    </Box>
  )
}

export default LoginPage
