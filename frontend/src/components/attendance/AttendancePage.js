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
  Chip,
  Tabs,
  Tab,
  IconButton,
} from '@mui/material';
import { Login, Logout, AccessTime, ChevronLeft, ChevronRight } from '@mui/icons-material';
import { useAuth } from '../../contexts/AuthContext';
import attendanceService from '../../services/attendanceService';

const AttendancePage = () => {
  const { user } = useAuth();
  const [todayAttendance, setTodayAttendance] = useState(null);
  const [monthlyAttendance, setMonthlyAttendance] = useState([]);
  const [allAttendance, setAllAttendance] = useState([]);
  const [currentDate, setCurrentDate] = useState(new Date());
  
  const isAdmin = user?.role === 'ADMIN';
  const [tabValue, setTabValue] = useState(isAdmin ? 1 : 0);

  // 초기 데이터 로드
  useEffect(() => {
    if (isAdmin && tabValue === 1) {
      fetchAllAttendance();
    } else if (tabValue === 0) {
      fetchTodayAttendance();
      fetchMonthlyAttendance();
    }
  }, [isAdmin, tabValue, currentDate]);

  const fetchTodayAttendance = async () => {
    try {
      const response = await attendanceService.getTodayAttendance();
      console.log('오늘 근태 응답:', response);
      if (response.success) {
        setTodayAttendance(response.data);
      }
    } catch (error) {
      console.error('오늘 근태 조회 실패:', error);
    }
  };

  const fetchMonthlyAttendance = async () => {
    try {
      const year = currentDate.getFullYear();
      const month = currentDate.getMonth() + 1;
      const response = await attendanceService.getMyAttendance(year, month);
      console.log('월별 근태 응답:', response);
      if (response.success) {
        setMonthlyAttendance(response.data);
      }
    } catch (error) {
      console.error('월별 근태 조회 실패:', error);
    }
  };

  const fetchAllAttendance = async () => {
    try {
      const dateStr = currentDate.toISOString().split('T')[0];
      console.log('전체 근태 조회 요청 - 날짜:', dateStr);
      
      const response = await attendanceService.getAllAttendance(dateStr);
      console.log('전체 근태 응답:', response);
      
      if (response.success) {
        console.log('조회된 데이터:', response.data);
        setAllAttendance(response.data);
      }
    } catch (error) {
      console.error('전체 근태 조회 실패:', error);
      console.error('에러 상세:', error.response);
    }
  };

  const handleCheckIn = async () => {
    try {
      const response = await attendanceService.checkIn();
      if (response.success) {
        alert('출근 처리되었습니다');
        fetchTodayAttendance();
        fetchMonthlyAttendance();
        if (isAdmin && tabValue === 1) fetchAllAttendance();
      }
    } catch (error) {
      console.error('출근 처리 실패:', error);
      alert(error.response?.data?.message || '출근 처리에 실패했습니다');
    }
  };

  const handleCheckOut = async () => {
    try {
      const response = await attendanceService.checkOut();
      if (response.success) {
        alert('퇴근 처리되었습니다');
        fetchTodayAttendance();
        fetchMonthlyAttendance();
        if (isAdmin && tabValue === 1) fetchAllAttendance();
      }
    } catch (error) {
      console.error('퇴근 처리 실패:', error);
      alert(error.response?.data?.message || '퇴근 처리에 실패했습니다');
    }
  };

  const handlePrevDay = () => {
    const newDate = new Date(currentDate);
    newDate.setDate(newDate.getDate() - 1);
    setCurrentDate(newDate);
  };

  const handleNextDay = () => {
    const newDate = new Date(currentDate);
    newDate.setDate(newDate.getDate() + 1);
    setCurrentDate(newDate);
  };

  const handleToday = () => {
    setCurrentDate(new Date());
  };

  const handlePrevMonth = () => {
    const newDate = new Date(currentDate);
    newDate.setMonth(newDate.getMonth() - 1);
    setCurrentDate(newDate);
  };

  const handleNextMonth = () => {
    const newDate = new Date(currentDate);
    newDate.setMonth(newDate.getMonth() + 1);
    setCurrentDate(newDate);
  };

  const formatTime = (dateTime) => {
    if (!dateTime) return '-';
    const date = new Date(dateTime);
    return date.toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  };

  const formatDate = (date) => {
    return date.toLocaleDateString('ko-KR', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
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

      {isAdmin && (
        <Paper sx={{ mb: 3 }}>
          <Tabs value={tabValue} onChange={(e, v) => setTabValue(v)}>
            <Tab label="내 근태" />
            <Tab label="전체 사원 근태" />
          </Tabs>
        </Paper>
      )}

      {tabValue === 0 && (
        <>
          {/* 출퇴근 버튼 */}
          <Grid container spacing={3} sx={{ mb: 3 }}>
            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                    <Login sx={{ fontSize: 40, mr: 2, color: 'primary.main' }} />
                    <Typography variant="h6">출근</Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    출근 시간: {todayAttendance?.checkIn ? formatTime(todayAttendance.checkIn) : '미출근'}
                  </Typography>
                  <Button
                    variant="contained"
                    fullWidth
                    onClick={handleCheckIn}
                    disabled={!!todayAttendance?.checkIn}
                  >
                    출근 체크
                  </Button>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                    <Logout sx={{ fontSize: 40, mr: 2, color: 'error.main' }} />
                    <Typography variant="h6">퇴근</Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    퇴근 시간: {todayAttendance?.checkOut ? formatTime(todayAttendance.checkOut) : '미퇴근'}
                  </Typography>
                  <Button
                    variant="contained"
                    color="error"
                    fullWidth
                    onClick={handleCheckOut}
                    disabled={!todayAttendance?.checkIn || !!todayAttendance?.checkOut}
                  >
                    퇴근 체크
                  </Button>
                </CardContent>
              </Card>
            </Grid>
          </Grid>

          {/* 오늘 근무 시간 */}
          {todayAttendance && (
            <Card sx={{ mb: 3 }}>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                  <AccessTime sx={{ fontSize: 40, mr: 2, color: 'success.main' }} />
                  <Typography variant="h6">오늘 근무 시간</Typography>
                </Box>
                <Typography variant="h4" color="primary">
                  {calculateWorkHours(todayAttendance.checkIn, todayAttendance.checkOut)}
                </Typography>
              </CardContent>
            </Card>
          )}

          {/* 월별 근태 현황 */}
          <Paper sx={{ p: 2 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
              <Typography variant="h6">
                {currentDate.getFullYear()}년 {currentDate.getMonth() + 1}월 근태 현황
              </Typography>
              <Box>
                <IconButton onClick={handlePrevMonth}>
                  <ChevronLeft />
                </IconButton>
                <Button size="small" onClick={handleToday}>
                  이번 달
                </Button>
                <IconButton onClick={handleNextMonth}>
                  <ChevronRight />
                </IconButton>
              </Box>
            </Box>

            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              총 출근일: {monthlyAttendance.length}일
            </Typography>

            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>날짜</TableCell>
                    <TableCell>출근 시간</TableCell>
                    <TableCell>퇴근 시간</TableCell>
                    <TableCell>근무 시간</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {monthlyAttendance.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={4} align="center">
                        근태 기록이 없습니다
                      </TableCell>
                    </TableRow>
                  ) : (
                    monthlyAttendance.map((record) => (
                      <TableRow key={record.id}>
                        <TableCell>{new Date(record.workDate).toLocaleDateString('ko-KR')}</TableCell>
                        <TableCell>{formatTime(record.checkIn)}</TableCell>
                        <TableCell>{formatTime(record.checkOut)}</TableCell>
                        <TableCell>{calculateWorkHours(record.checkIn, record.checkOut)}</TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>
        </>
      )}

      {tabValue === 1 && isAdmin && (
        <Paper sx={{ p: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
            <Typography variant="h6">
              {formatDate(currentDate)} 전체 사원 근태
            </Typography>
            <Box>
              <IconButton onClick={handlePrevDay}>
                <ChevronLeft />
              </IconButton>
              <Button size="small" onClick={handleToday}>
                오늘
              </Button>
              <IconButton onClick={handleNextDay}>
                <ChevronRight />
              </IconButton>
            </Box>
          </Box>

          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            총 출근: {allAttendance.length}명
          </Typography>

          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>사번</TableCell>
                  <TableCell>이름</TableCell>
                  <TableCell>부서/팀</TableCell>
                  <TableCell>출근 시간</TableCell>
                  <TableCell>퇴근 시간</TableCell>
                  <TableCell>근무 시간</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {allAttendance.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} align="center">
                      근태 기록이 없습니다
                    </TableCell>
                  </TableRow>
                ) : (
                  allAttendance.map((record) => (
                    <TableRow key={record.id}>
                      <TableCell>{record.employeeId}</TableCell>
                      <TableCell>{record.employeeName}</TableCell>
                      <TableCell>
                        {record.departmentName} / {record.teamName}
                      </TableCell>
                      <TableCell>{formatTime(record.checkIn)}</TableCell>
                      <TableCell>{formatTime(record.checkOut)}</TableCell>
                      <TableCell>{calculateWorkHours(record.checkIn, record.checkOut)}</TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>
      )}
    </Container>
  );
};

export default AttendancePage;