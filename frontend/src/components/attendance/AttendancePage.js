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
  Chip,
  TextField,
  Grid,
  Card,
  CardContent,
} from '@mui/material';
import { Login, Logout, Schedule } from '@mui/icons-material';
import { useAuth } from '../../contexts/AuthContext';
import { useSecurityMode } from '../../contexts/SecurityModeContext';
import attendanceService from '../../services/attendanceService';

const AttendancePage = () => {
  const { user } = useAuth();
  const { isSecure } = useSecurityMode();
  const [attendances, setAttendances] = useState([]);
  const [todayAttendance, setTodayAttendance] = useState(null);
  const [startDate, setStartDate] = useState(
    new Date(new Date().getFullYear(), new Date().getMonth(), 1).toISOString().split('T')[0]
  );
  const [endDate, setEndDate] = useState(new Date().toISOString().split('T')[0]);

  // Vulnerable 모드용 시간 조작
  const [customCheckInTime, setCustomCheckInTime] = useState('');
  const [customCheckOutTime, setCustomCheckOutTime] = useState('');

  useEffect(() => {
    fetchAttendances();
  }, [startDate, endDate]);

  const fetchAttendances = async () => {
    try {
      const response = await attendanceService.getMyAttendances(startDate, endDate);
      if (response.success) {
        setAttendances(response.data);
        
        const today = new Date().toISOString().split('T')[0];
        const todayRecord = response.data.find(a => a.workDate === today);
        setTodayAttendance(todayRecord);
      }
    } catch (error) {
      console.error('근태 조회 실패:', error);
    }
  };

  const handleCheckIn = async () => {
    try {
      let checkInTime = null;
      
      if (!isSecure && customCheckInTime) {
        checkInTime = new Date(customCheckInTime).toISOString();
      }

      const response = await attendanceService.checkIn(checkInTime);
      
      if (response.success) {
        alert('출근 처리되었습니다');
        fetchAttendances();
      }
    } catch (error) {
      console.error('출근 실패:', error);
      alert(error.response?.data?.message || '출근 처리에 실패했습니다');
    }
  };

  const handleCheckOut = async () => {
    try {
      let checkOutTime = null;
      
      if (!isSecure && customCheckOutTime) {
        checkOutTime = new Date(customCheckOutTime).toISOString();
      }

      const response = await attendanceService.checkOut(checkOutTime);
      
      if (response.success) {
        alert('퇴근 처리되었습니다');
        fetchAttendances();
      }
    } catch (error) {
      console.error('퇴근 실패:', error);
      alert(error.response?.data?.message || '퇴근 처리에 실패했습니다');
    }
  };

  const getStatusColor = (status) => {
    const colors = {
      PRESENT: 'success',
      LATE: 'warning',
      EARLY_LEAVE: 'warning',
      ABSENT: 'error',
      VACATION: 'info',
      HALF_VACATION: 'info',
      SICK_LEAVE: 'secondary',
      BUSINESS_TRIP: 'primary',
    };
    return colors[status] || 'default';
  };

  const getStatusLabel = (status) => {
    const labels = {
      PRESENT: '정상',
      LATE: '지각',
      EARLY_LEAVE: '조퇴',
      ABSENT: '결근',
      VACATION: '휴가',
      HALF_VACATION: '반차',
      SICK_LEAVE: '병가',
      BUSINESS_TRIP: '출장',
    };
    return labels[status] || status;
  };

  const formatDateTime = (dateString) => {
    if (!dateString) return '-';
    const date = new Date(dateString);
    return date.toLocaleTimeString('ko-KR');
  };

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      <Typography variant="h4" gutterBottom>
        근태 관리
      </Typography>

      {!isSecure && (
        <Box sx={{ mb: 2, p: 2, bgcolor: 'error.light', borderRadius: 1 }}>
          <Typography variant="body2" color="error.contrastText">
            ⚠️ 취약 모드: 출퇴근 시간 조작이 가능합니다
          </Typography>
        </Box>
      )}

      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                오늘의 출퇴근
              </Typography>
              
              {!isSecure && (
                <Box sx={{ mb: 2, p: 1, bgcolor: 'warning.light', borderRadius: 1 }}>
                  <Typography variant="caption">
                    시간 조작 (취약 모드)
                  </Typography>
                  <TextField
                    fullWidth
                    type="datetime-local"
                    label="출근 시간"
                    value={customCheckInTime}
                    onChange={(e) => setCustomCheckInTime(e.target.value)}
                    size="small"
                    sx={{ mt: 1, mb: 1 }}
                    InputLabelProps={{ shrink: true }}
                  />
                  <TextField
                    fullWidth
                    type="datetime-local"
                    label="퇴근 시간"
                    value={customCheckOutTime}
                    onChange={(e) => setCustomCheckOutTime(e.target.value)}
                    size="small"
                    InputLabelProps={{ shrink: true }}
                  />
                </Box>
              )}

              <Box sx={{ display: 'flex', gap: 2 }}>
                <Button
                  variant="contained"
                  color="primary"
                  startIcon={<Login />}
                  onClick={handleCheckIn}
                  disabled={todayAttendance?.checkIn}
                  fullWidth
                >
                  출근
                </Button>
                <Button
                  variant="contained"
                  color="secondary"
                  startIcon={<Logout />}
                  onClick={handleCheckOut}
                  disabled={!todayAttendance?.checkIn || todayAttendance?.checkOut}
                  fullWidth
                >
                  퇴근
                </Button>
              </Box>

              {todayAttendance && (
                <Box sx={{ mt: 2 }}>
                  <Typography variant="body2">
                    출근: {formatDateTime(todayAttendance.checkIn)}
                  </Typography>
                  <Typography variant="body2">
                    퇴근: {formatDateTime(todayAttendance.checkOut)}
                  </Typography>
                  <Chip
                    label={getStatusLabel(todayAttendance.status)}
                    color={getStatusColor(todayAttendance.status)}
                    size="small"
                    sx={{ mt: 1 }}
                  />
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                근태 통계
              </Typography>
              <Typography variant="body2">
                정상 출근: {attendances.filter(a => a.status === 'PRESENT').length}일
              </Typography>
              <Typography variant="body2">
                지각: {attendances.filter(a => a.status === 'LATE').length}일
              </Typography>
              <Typography variant="body2">
                조퇴: {attendances.filter(a => a.status === 'EARLY_LEAVE').length}일
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Paper sx={{ p: 3, mb: 3 }}>
        <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
          <TextField
            label="시작일"
            type="date"
            value={startDate}
            onChange={(e) => setStartDate(e.target.value)}
            InputLabelProps={{ shrink: true }}
          />
          <TextField
            label="종료일"
            type="date"
            value={endDate}
            onChange={(e) => setEndDate(e.target.value)}
            InputLabelProps={{ shrink: true }}
          />
        </Box>
      </Paper>

      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell align="center">날짜</TableCell>
              <TableCell align="center">출근 시간</TableCell>
              <TableCell align="center">퇴근 시간</TableCell>
              <TableCell align="center">상태</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {attendances.length === 0 ? (
              <TableRow>
                <TableCell colSpan={4} align="center">
                  근태 기록이 없습니다
                </TableCell>
              </TableRow>
            ) : (
              attendances.map((attendance) => (
                <TableRow key={attendance.id}>
                  <TableCell align="center">{attendance.workDate}</TableCell>
                  <TableCell align="center">{formatDateTime(attendance.checkIn)}</TableCell>
                  <TableCell align="center">{formatDateTime(attendance.checkOut)}</TableCell>
                  <TableCell align="center">
                    <Chip
                      label={getStatusLabel(attendance.status)}
                      color={getStatusColor(attendance.status)}
                      size="small"
                    />
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </TableContainer>
    </Container>
  );
};

export default AttendancePage;