import React, { useState, useEffect } from 'react';
import {
  Container,
  Paper,
  Typography,
  Button,
  Box,
  Card,
  CardContent,
  CardActions,
  Grid,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  IconButton,
} from '@mui/material';
import { Add, Delete, DateRange } from '@mui/icons-material';
import { useAuth } from '../../contexts/AuthContext';
import scheduleService from '../../services/scheduleService';

const ScheduleList = () => {
  const { user } = useAuth();
  const [schedules, setSchedules] = useState([]);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [formData, setFormData] = useState({
    title: '',
    content: '',
    startDate: '',
    endDate: '',
    assigneeId: null,
  });

  useEffect(() => {
    if (user?.teamId) {
      fetchSchedules();
    }
  }, [user]);

  const fetchSchedules = async () => {
    try {
      const response = await scheduleService.getTeamSchedules(user.teamId);
      if (response.success) {
        setSchedules(response.data);
      }
    } catch (error) {
      console.error('일정 조회 실패:', error);
    }
  };

  const handleSubmit = async () => {
    if (!formData.title || !formData.startDate || !formData.endDate) {
      alert('필수 항목을 입력하세요');
      return;
    }

    try {
      const response = await scheduleService.createSchedule(user.teamId, {
        ...formData,
        startDate: new Date(formData.startDate).toISOString(),
        endDate: new Date(formData.endDate).toISOString(),
      });

      if (response.success) {
        alert('일정이 등록되었습니다');
        setDialogOpen(false);
        setFormData({
          title: '',
          content: '',
          startDate: '',
          endDate: '',
          assigneeId: null,
        });
        fetchSchedules();
      }
    } catch (error) {
      console.error('일정 등록 실패:', error);
      alert(error.response?.data?.message || '일정 등록에 실패했습니다');
    }
  };

  const handleDelete = async (scheduleId) => {
    if (!window.confirm('일정을 삭제하시겠습니까?')) return;

    try {
      const response = await scheduleService.deleteSchedule(user.teamId, scheduleId);
      if (response.success) {
        alert('일정이 삭제되었습니다');
        fetchSchedules();
      }
    } catch (error) {
      console.error('일정 삭제 실패:', error);
      alert(error.response?.data?.message || '일정 삭제에 실패했습니다');
    }
  };

  const formatDateTime = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleString('ko-KR');
  };

  if (!user?.teamId) {
    return (
      <Container maxWidth="lg" sx={{ mt: 4 }}>
        <Typography>팀에 소속되어 있지 않습니다</Typography>
      </Container>
    );
  }

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 3 }}>
        <Typography variant="h4">팀 일정</Typography>
        <Button
          variant="contained"
          startIcon={<Add />}
          onClick={() => setDialogOpen(true)}
        >
          일정 추가
        </Button>
      </Box>

      <Grid container spacing={3}>
        {schedules.length === 0 ? (
          <Grid item xs={12}>
            <Paper sx={{ p: 3, textAlign: 'center' }}>
              <Typography color="text.secondary">등록된 일정이 없습니다</Typography>
            </Paper>
          </Grid>
        ) : (
          schedules.map((schedule) => (
            <Grid item xs={12} md={6} key={schedule.id}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                    <DateRange sx={{ mr: 1, color: 'primary.main' }} />
                    <Typography variant="h6">{schedule.title}</Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    {schedule.content}
                  </Typography>
                  <Typography variant="body2" sx={{ mt: 2 }}>
                    시작: {formatDateTime(schedule.startDate)}
                  </Typography>
                  <Typography variant="body2">
                    종료: {formatDateTime(schedule.endDate)}
                  </Typography>
                  {schedule.assigneeName && (
                    <Typography variant="body2" sx={{ mt: 1 }}>
                      담당자: {schedule.assigneeName}
                    </Typography>
                  )}
                </CardContent>
                <CardActions>
                  <IconButton
                    size="small"
                    color="error"
                    onClick={() => handleDelete(schedule.id)}
                  >
                    <Delete />
                  </IconButton>
                </CardActions>
              </Card>
            </Grid>
          ))
        )}
      </Grid>

      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>일정 추가</DialogTitle>
        <DialogContent>
          <TextField
            fullWidth
            label="제목"
            value={formData.title}
            onChange={(e) => setFormData({ ...formData, title: e.target.value })}
            sx={{ mt: 2, mb: 2 }}
            required
          />
          <TextField
            fullWidth
            label="내용"
            multiline
            rows={3}
            value={formData.content}
            onChange={(e) => setFormData({ ...formData, content: e.target.value })}
            sx={{ mb: 2 }}
          />
          <TextField
            fullWidth
            label="시작 날짜"
            type="datetime-local"
            value={formData.startDate}
            onChange={(e) => setFormData({ ...formData, startDate: e.target.value })}
            InputLabelProps={{ shrink: true }}
            sx={{ mb: 2 }}
            required
          />
          <TextField
            fullWidth
            label="종료 날짜"
            type="datetime-local"
            value={formData.endDate}
            onChange={(e) => setFormData({ ...formData, endDate: e.target.value })}
            InputLabelProps={{ shrink: true }}
            required
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialogOpen(false)}>취소</Button>
          <Button onClick={handleSubmit} variant="contained">등록</Button>
        </DialogActions>
      </Dialog>
    </Container>
  );
};

export default ScheduleList;