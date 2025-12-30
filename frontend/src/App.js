import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom"
import { ThemeProvider, createTheme } from "@mui/material/styles"
import CssBaseline from "@mui/material/CssBaseline"
import { Box } from "@mui/material"

import { AuthProvider } from "./contexts/AuthContext"
import { SecurityModeProvider } from "./contexts/SecurityModeContext"

import Header from "./components/common/Header"
import Sidebar from "./components/common/Sidebar"
import PrivateRoute from "./components/common/PrivateRoute"

import LoginPage from "./pages/login/LoginPage"
import DashboardPage from "./pages/dashboard/DashboardPage"
import BoardList from "./components/board/BoardList"
import BoardDetail from "./components/board/BoardDetail"
import BoardForm from "./components/board/BoardForm"
import ScheduleList from "./components/schedule/ScheduleList"
import AttendancePage from "./components/attendance/AttendancePage"
import FilePage from "./components/file/FilePage"
import SuggestionPage from "./components/suggestion/SuggestionPage"
import CafeteriaPage from "./components/cafeteria/CafeteriaPage"
import ApprovalPage from "./components/approval/ApprovalPage"

const theme = createTheme({
  palette: {
    primary: {
      main: "#1e3a5f",
      light: "#2d5278",
      dark: "#152940",
      contrastText: "#ffffff",
    },
    secondary: {
      main: "#3b7ea1",
      light: "#5394b8",
      dark: "#2a5971",
      contrastText: "#ffffff",
    },
    background: {
      default: "#f5f7fa",
      paper: "#ffffff",
    },
    text: {
      primary: "#1a2332",
      secondary: "#6b7280",
    },
    success: {
      main: "#10b981",
      light: "#34d399",
      dark: "#059669",
    },
    error: {
      main: "#ef4444",
      light: "#f87171",
      dark: "#dc2626",
    },
    warning: {
      main: "#f59e0b",
      light: "#fbbf24",
      dark: "#d97706",
    },
    info: {
      main: "#3b82f6",
      light: "#60a5fa",
      dark: "#2563eb",
    },
  },
  typography: {
    fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", "Roboto", sans-serif',
    h4: {
      fontWeight: 700,
      fontSize: "2rem",
      lineHeight: 1.3,
      letterSpacing: "-0.02em",
    },
    h5: {
      fontWeight: 600,
      fontSize: "1.5rem",
      lineHeight: 1.4,
      letterSpacing: "-0.01em",
    },
    h6: {
      fontWeight: 600,
      fontSize: "1.125rem",
      lineHeight: 1.5,
    },
    body1: {
      fontSize: "0.9375rem",
      lineHeight: 1.6,
    },
    body2: {
      fontSize: "0.875rem",
      lineHeight: 1.6,
    },
    button: {
      textTransform: "none",
      fontWeight: 500,
    },
  },
  shape: {
    borderRadius: 8,
  },
  shadows: [
    "none",
    "0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06)",
    "0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)",
    "0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)",
    "0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)",
    "0 25px 50px -12px rgba(0, 0, 0, 0.25)",
    ...Array(19).fill("none"),
  ],
  components: {
    MuiButton: {
      styleOverrides: {
        root: {
          boxShadow: "none",
          "&:hover": {
            boxShadow: "none",
          },
        },
        contained: {
          "&:hover": {
            transform: "translateY(-1px)",
            transition: "all 0.2s ease-in-out",
          },
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          boxShadow: "0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06)",
          "&:hover": {
            boxShadow: "0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)",
            transition: "all 0.2s ease-in-out",
          },
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          boxShadow: "0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06)",
        },
        elevation3: {
          boxShadow: "0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)",
        },
      },
    },
    MuiTableCell: {
      styleOverrides: {
        head: {
          fontWeight: 600,
          backgroundColor: "#f9fafb",
          color: "#374151",
        },
      },
    },
  },
})

function App() {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <AuthProvider>
        <SecurityModeProvider>
          <Router>
            <Routes>
              <Route path="/login" element={<LoginPage />} />

              <Route
                path="/*"
                element={
                  <PrivateRoute>
                    <Box sx={{ display: "flex", minHeight: "100vh" }}>
                      <Header />
                      <Sidebar />
                      <Box
                        component="main"
                        sx={{
                          flexGrow: 1,
                          marginTop: "64px",
                          marginLeft: "260px",
                          padding: "32px",
                          backgroundColor: "#f5f7fa",
                          minHeight: "calc(100vh - 64px)",
                        }}
                      >
                        <Routes>
                          <Route path="/" element={<Navigate to="/dashboard" />} />
                          <Route path="/dashboard" element={<DashboardPage />} />

                          {/* 게시판 */}
                          <Route path="/boards" element={<BoardList />} />
                          <Route path="/boards/new" element={<BoardForm />} />
                          <Route path="/boards/:id" element={<BoardDetail />} />
                          <Route path="/boards/:id/edit" element={<BoardForm />} />

                          {/* 팀 일정 */}
                          <Route path="/schedules" element={<ScheduleList />} />

                          {/* 근태 관리 */}
                          <Route path="/attendance" element={<AttendancePage />} />

                          {/* 팀 자료실 */}
                          <Route path="/files" element={<FilePage />} />

                          {/* 익명 건의함 */}
                          <Route path="/suggestions" element={<SuggestionPage />} />

                          {/* 구내식당 */}
                          <Route path="/cafeteria" element={<CafeteriaPage />} />

                          {/* 전자결재 */}
                          <Route path="/approvals" element={<ApprovalPage />} />

                          <Route path="*" element={<Navigate to="/dashboard" />} />
                        </Routes>
                      </Box>
                    </Box>
                  </PrivateRoute>
                }
              />
            </Routes>
          </Router>
        </SecurityModeProvider>
      </AuthProvider>
    </ThemeProvider>
  )
}

export default App
