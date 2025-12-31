// src/pages/auth/LoginPage.jsx

"use client"

import { useState } from "react"
import { 
  Container, Box, TextField, Button, Typography, Paper, 
  Alert, CircularProgress, Divider, FormControl, 
  FormLabel, RadioGroup, FormControlLabel, Radio, Chip 
} from "@mui/material"
import { BusinessCenter, Lock, Person, Security, Warning } from "@mui/icons-material"
import { useAuth } from "../../contexts/AuthContext"
import { useNavigate } from "react-router-dom"
import authService from "../../services/authService"

const LoginPage = () => {
  const [employeeId, setEmployeeId] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)
  const [securityMode, setSecurityMode] = useState(authService.getSecurityMode())

  const { login } = useAuth()
  const navigate = useNavigate()

  const handleSecurityModeChange = (event) => {
    const mode = event.target.value
    setSecurityMode(mode)
    authService.setSecurityMode(mode)
    console.log('보안 모드 변경:', mode)
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError("")
    setLoading(true)

    console.log("로그인 시도:", employeeId)
    console.log("보안 모드:", securityMode)

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

            {/* 보안 모드 선택 UI */}
            <Paper 
              elevation={0} 
              sx={{ 
                p: 2, 
                mb: 3, 
                bgcolor: securityMode === 'secure' ? '#e8f5e9' : '#fff3e0',
                border: '1px solid',
                borderColor: securityMode === 'secure' ? '#4caf50' : '#ff9800'
              }}
            >
              <FormControl component="fieldset" fullWidth>
                <FormLabel component="legend" sx={{ mb: 1, display: 'flex', alignItems: 'center', gap: 1 }}>
                  {securityMode === 'secure' ? <Security color="success" /> : <Warning color="warning" />}
                  <Typography variant="subtitle2" fontWeight={600}>
                    보안 모드
                  </Typography>
                </FormLabel>
                <RadioGroup
                  row
                  value={securityMode}
                  onChange={handleSecurityModeChange}
                >
                  <FormControlLabel 
                    value="secure" 
                    control={<Radio />} 
                    label={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <span>보안 모드</span>
                        <Chip 
                          label="SHA-256" 
                          size="small" 
                          color="success" 
                          sx={{ height: 20 }}
                        />
                      </Box>
                    }
                  />
                  <FormControlLabel 
                    value="vulnerable" 
                    control={<Radio />} 
                    label={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <span>취약 모드</span>
                        <Chip 
                          label="평문" 
                          size="small" 
                          color="warning" 
                          sx={{ height: 20 }}
                        />
                      </Box>
                    }
                  />
                </RadioGroup>
              </FormControl>
              
              <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                {securityMode === 'secure' 
                  ? '✓ 비밀번호가 SHA-256으로 해시되어 전송됩니다' 
                  : '⚠ 비밀번호가 평문으로 전송됩니다 (교육용)'}
              </Typography>
            </Paper>

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