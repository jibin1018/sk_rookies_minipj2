import React, { useState, useEffect } from 'react';
import {
  Container,
  Paper,
  Typography,
  Button,
  Box,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Card,
  CardContent,
  Grid,
} from '@mui/material';
import { Login, Logout, AccessTime } from '@mui/icons-material';
import { useAuth } from '../../contexts/AuthContext';
import attendanceService from '../../services/attendanceService';

const AttendancePage = () => {
  const { user } = useAuth();
  const [attendances, setAttendances] = useState([]);
  const [todayAttendance, setTodayAttendance] = useState(null);

  // 이번 달 첫날과 오늘 날짜
  const today = new Date();
  const firstDay = new Date(today.getFullYear(), today.getMonth(), 1);
  const [startDate] = useState(firstDay.toISOString().split('T')[0]);
  const [endDate] = useState(today.toISOString().split('T')[0]);

  useEffect(() => {
    fetchAttendances();
  }, []);

  const fetchAttendances = async () => {
    try {
      const response = await attendanceService.getMyAttendances(startDate, endDate);
      
      if (response.success) {
        setAttendances(response.data);
        
        // 오늘 날짜의 근태 찾기
        const todayStr = new Date().toISOString().split('T')[0];
        const todayRecord = response.data.find(a => a.workDate === todayStr);
        setTodayAttendance(todayRecord);
      }
    } catch (error) {
      console.error('근태 조회 실패:', error);
    }
  };

  const handleCheckIn = async () => {
    if (todayAttendance?.checkIn) {
      alert('이미 출근 처리되었습니다');
      return;
    }

    try {
      const response = await attendanceService.checkIn();
      
      if (response.success) {
        const now = new Date();
        const timeStr = now.toLocaleTimeString('ko-KR');
        alert(`출근 완료: ${timeStr}`);
        fetchAttendances();
      }
    } catch (error) {
      console.error('출근 실패:', error);
      alert(error.response?.data?.message || '출근 처리에 실패했습니다');
    }
  };

  const handleCheckOut = async () => {
    if (!todayAttendance?.checkIn) {
      alert('출근 기록이 없습니다');
      return;
    }

    if (todayAttendance?.checkOut) {
      alert('이미 퇴근 처리되었습니다');
      return;
    }

    try {
      const response = await attendanceService.checkOut();
      
      if (response.success) {
        const now = new Date();
        const timeStr = now.toLocaleTimeString('ko-KR');
        alert(`퇴근 완료: ${timeStr}`);
        fetchAttendances();
      }
    } catch (error) {
      console.error('퇴근 실패:', error);
      alert(error.response?.data?.message || '퇴근 처리에 실패했습니다');
    }
  };

  const formatTime = (dateString) => {
    if (!dateString) return '-';
    const date = new Date(dateString);
    return date.toLocaleTimeString('ko-KR', { 
      hour: '2-digit', 
      minute: '2-digit',
      second: '2-digit',
      hour12: false 
    });
  };

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('ko-KR', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      weekday: 'short'
    });
  };

  const calculateWorkHours = (checkIn, checkOut) => {
    if (!checkIn || !checkOut) return '-';
    
    const start = new Date(checkIn);
    const end = new Date(checkOut);
    const diff = end - start;
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
    
    return `${hours}시간 ${minutes}분`;
  };

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      <Typography variant="h4" gutterBottom>
        근태 관리
      </Typography>

      <Grid container spacing={3} sx={{ mb: 3 }}>
        {/* 오늘의 출퇴근 */}
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <AccessTime sx={{ mr: 1, fontSize: 28, color: 'primary.main' }} />
                <Typography variant="h6">
                  오늘의 출퇴근 ({new Date().toLocaleDateString('ko-KR')})
                </Typography>
              </Box>
              
              <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={6}>
                  <Paper sx={{ p: 2, bgcolor: 'primary.light' }}>
                    <Typography variant="body2" color="primary.contrastText" gutterBottom>
                      출근 시간
                    </Typography>
                    <Typography variant="h5" color="primary.contrastText">
                      {todayAttendance?.checkIn ? formatTime(todayAttendance.checkIn) : '미등록'}
                    </Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6}>
                  <Paper sx={{ p: 2, bgcolor: 'secondary.light' }}>
                    <Typography variant="body2" color="secondary.contrastText" gutterBottom>
                      퇴근 시간
                    </Typography>
                    <Typography variant="h5" color="secondary.contrastText">
                      {todayAttendance?.checkOut ? formatTime(todayAttendance.checkOut) : '미등록'}
                    </Typography>
                  </Paper>
                </Grid>
              </Grid>

              {todayAttendance?.checkIn && todayAttendance?.checkOut && (
                <Box sx={{ mb: 2, p: 2, bgcolor: 'grey.100', borderRadius: 1 }}>
                  <Typography variant="body2" color="text.secondary">
                    총 근무시간: <strong>{calculateWorkHours(todayAttendance.checkIn, todayAttendance.checkOut)}</strong>
                  </Typography>
                </Box>
              )}

              <Box sx={{ display: 'flex', gap: 2 }}>
                <Button
                  variant="contained"
                  color="primary"
                  size="large"
                  startIcon={<Login />}
                  onClick={handleCheckIn}
                  disabled={!!todayAttendance?.checkIn}
                  fullWidth
                >
                  출근
                </Button>
                <Button
                  variant="contained"
                  color="secondary"
                  size="large"
                  startIcon={<Logout />}
                  onClick={handleCheckOut}
                  disabled={!todayAttendance?.checkIn || !!todayAttendance?.checkOut}
                  fullWidth
                >
                  퇴근
                </Button>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* 이번 달 통계 */}
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                이번 달 출근 현황
              </Typography>
              <Box sx={{ mt: 2 }}>
                <Typography variant="h3" color="primary.main" align="center">
                  {attendances.length}
                </Typography>
                <Typography variant="body2" color="text.secondary" align="center">
                  일 출근
                </Typography>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* 근태 기록 */}
      <Paper>
        <Box sx={{ p: 2, borderBottom: 1, borderColor: 'divider' }}>
          <Typography variant="h6">이번 달 근태 기록</Typography>
        </Box>
        
        <TableContainer>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>날짜</TableCell>
                <TableCell align="center">출근 시간</TableCell>
                <TableCell align="center">퇴근 시간</TableCell>
                <TableCell align="center">근무 시간</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {attendances.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={4} align="center" sx={{ py: 4 }}>
                    <Typography color="text.secondary">
                      이번 달 근태 기록이 없습니다
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : (
                attendances.slice().reverse().map((attendance) => (
                  <TableRow key={attendance.id}>
                    <TableCell>{formatDate(attendance.workDate)}</TableCell>
                    <TableCell align="center">
                      <Typography color="primary.main" fontWeight="medium">
                        {formatTime(attendance.checkIn)}
                      </Typography>
                    </TableCell>
                    <TableCell align="center">
                      <Typography color="secondary.main" fontWeight="medium">
                        {formatTime(attendance.checkOut)}
                      </Typography>
                    </TableCell>
                    <TableCell align="center">
                      {calculateWorkHours(attendance.checkIn, attendance.checkOut)}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>
    </Container>
  );
};

export default AttendancePage;