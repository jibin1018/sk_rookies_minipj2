// src/App.js

import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom"
import { ThemeProvider, createTheme } from "@mui/material/styles"
import CssBaseline from "@mui/material/CssBaseline"
import { Box } from "@mui/material"

import { AuthProvider } from "./contexts/AuthContext"

import Header from "./components/common/Header"
import Sidebar from "./components/common/Sidebar"
import PrivateRoute from "./components/common/PrivateRoute"

import LoginPage from "./pages/login/LoginPage"
import DashboardPage from "./pages/dashboard/DashboardPage"
import EmployeeManagementPage from "./pages/employee/EmployeeManagementPage"
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
      main: "#1a1a1a",
      light: "#2e2e2e",
      dark: "#0a0a0a",
      contrastText: "#ffffff",
    },
    secondary: {
      main: "#0f62fe",
      light: "#4589ff",
      dark: "#0043ce",
      contrastText: "#ffffff",
    },
    background: {
      default: "#ffffff",
      paper: "#ffffff",
    },
    text: {
      primary: "#37352f",
      secondary: "#787774",
    },
    divider: "rgba(55, 53, 47, 0.09)",
    success: {
      main: "#16a34a",
    },
    error: {
      main: "#dc2626",
    },
    warning: {
      main: "#f59e0b",
    },
    info: {
      main: "#0284c7",
    },
  },
  typography: {
    fontFamily:
      '-apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans KR", Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji"',
    h4: {
      fontWeight: 700,
      fontSize: "2.125rem",
      color: "#37352f",
      letterSpacing: "-0.01em",
    },
    h5: {
      fontWeight: 600,
      fontSize: "1.75rem",
      color: "#37352f",
      letterSpacing: "-0.01em",
    },
    h6: {
      fontWeight: 600,
      fontSize: "1.375rem",
      color: "#37352f",
      letterSpacing: "-0.005em",
    },
    body1: {
      fontSize: "1.0625rem",
      lineHeight: 1.6,
      color: "#37352f",
      letterSpacing: "0",
    },
    body2: {
      fontSize: "1rem",
      lineHeight: 1.5,
      color: "#787774",
      letterSpacing: "0",
    },
    button: {
      textTransform: "none",
      fontWeight: 500,
      fontSize: "1rem",
      letterSpacing: "0",
    },
  },
  shape: {
    borderRadius: 8,
  },
  components: {
    MuiButton: {
      styleOverrides: {
        root: {
          boxShadow: "none",
          padding: "12px 20px",
          "&:hover": {
            boxShadow: "none",
          },
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          border: "none",
          boxShadow:
            "rgba(15, 15, 15, 0.05) 0px 0px 0px 1px, rgba(15, 15, 15, 0.1) 0px 3px 6px, rgba(15, 15, 15, 0.2) 0px 9px 24px",
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          border: "none",
          boxShadow: "rgba(15, 15, 15, 0.05) 0px 0px 0px 1px",
        },
      },
    },
    MuiTableCell: {
      styleOverrides: {
        head: {
          fontWeight: 600,
          fontSize: "1rem",
          backgroundColor: "rgba(242, 241, 238, 0.6)",
          color: "#37352f",
          borderBottom: "1px solid rgba(55, 53, 47, 0.09)",
        },
        body: {
          fontSize: "1rem",
          borderBottom: "1px solid rgba(55, 53, 47, 0.09)",
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
        <Router>
          <Routes>
            <Route path="/login" element={<LoginPage />} />

            <Route
              path="/*"
              element={
                <PrivateRoute>
                  <Box sx={{ display: "flex", minHeight: "100vh", backgroundColor: "#ffffff" }}>
                    <Header />
                    <Sidebar />
                    <Box
                      component="main"
                      sx={{
                        flexGrow: 1,
                        marginTop: "56px",
                        marginLeft: "240px",
                        padding: "48px 96px 96px",
                        backgroundColor: "#ffffff",
                        minHeight: "calc(100vh - 56px)",
                        maxWidth: "1600px",
                        margin: "56px auto 0",
                        paddingLeft: "240px",
                      }}
                    >
                      <Routes>
                        <Route path="/" element={<Navigate to="/dashboard" />} />
                        <Route path="/dashboard" element={<DashboardPage />} />

                        <Route path="/boards" element={<BoardList />} />
                        <Route path="/boards/new" element={<BoardForm />} />
                        <Route path="/boards/:id" element={<BoardDetail />} />
                        <Route path="/boards/:id/edit" element={<BoardForm />} />

                        <Route path="/schedules" element={<ScheduleList />} />
                        <Route path="/attendance" element={<AttendancePage />} />
                        <Route path="/files" element={<FilePage />} />
                        <Route path="/suggestions" element={<SuggestionPage />} />
                        <Route path="/cafeteria" element={<CafeteriaPage />} />
                        <Route path="/approvals" element={<ApprovalPage />} />

                        <Route
                          path="/employees"
                          element={
                            <PrivateRoute adminOnly={true}>
                              <EmployeeManagementPage />
                            </PrivateRoute>
                          }
                        />

                        <Route path="*" element={<Navigate to="/dashboard" />} />
                      </Routes>
                    </Box>
                  </Box>
                </PrivateRoute>
              }
            />
          </Routes>
        </Router>
      </AuthProvider>
    </ThemeProvider>
  )
}

export default App