import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { Box } from '@mui/material';

import { AuthProvider } from './contexts/AuthContext';
import { SecurityModeProvider } from './contexts/SecurityModeContext';

import Header from './components/common/Header';
import Sidebar from './components/common/Sidebar';
import PrivateRoute from './components/common/PrivateRoute';

import LoginPage from './pages/login/LoginPage';
import DashboardPage from './pages/dashboard/DashboardPage';

// Board
import BoardList from './components/board/BoardList';
import BoardDetail from './components/board/BoardDetail';
import BoardForm from './components/board/BoardForm';

// Schedule
import ScheduleList from './components/schedule/ScheduleList';

// Attendance
import AttendancePage from './components/attendance/AttendancePage';

// File
import FilePage from './components/file/FilePage';

// Suggestion
import SuggestionPage from './components/suggestion/SuggestionPage';

// Cafeteria
import CafeteriaPage from './components/cafeteria/CafeteriaPage';

// Approval
import ApprovalPage from './components/approval/ApprovalPage';

const theme = createTheme({
  palette: {
    primary: {
      main: '#1976d2',
    },
    secondary: {
      main: '#dc004e',
    },
  },
});

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
                    <Box sx={{ display: 'flex' }}>
                      <Header />
                      <Sidebar />
                      <Box
                        component="main"
                        sx={{
                          flexGrow: 1,
                          p: 3,
                          mt: 8,
                          ml: '240px',
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
                          
                          <Route path="*" element={<DashboardPage />} />
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
  );
}

export default App;