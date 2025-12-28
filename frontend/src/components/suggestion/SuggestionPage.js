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
  Chip,
  Tabs,
  Tab,
} from '@mui/material';
import { Add, Feedback } from '@mui/icons-material';
import { useAuth } from '../../contexts/AuthContext';
import suggestionService from '../../services/suggestionService';

const SuggestionPage = () => {
  const { user } = useAuth();
  const [tabValue, setTabValue] = useState(0);
  const [suggestions, setSuggestions] = useState([]);
  const [mySuggestions, setMySuggestions] = useState([]);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [formData, setFormData] = useState({
    title: '',
    content: '',
  });

  useEffect(() => {
    fetchSuggestions();
    fetchMySuggestions();
  }, []);

  const fetchSuggestions = async () => {
    try {
      const response = await suggestionService.getAllSuggestions(0, 20);
      if (response.success) {
        setSuggestions(response.data.content);
      }
    } catch (error) {
      console.error('건의사항 조회 실패:', error);
    }
  };

  const fetchMySuggestions = async () => {
    try {
      const response = await suggestionService.getMySuggestions();
      if (response.success) {
        setMySuggestions(response.data);
      }
    } catch (error) {
      console.error('내 건의사항 조회 실패:', error);
    }
  };

  const handleSubmit = async () => {
    if (!formData.title || !formData.content) {
      alert('제목과 내용을 입력하세요');
      return;
    }

    try {
      const response = await suggestionService.createSuggestion(formData);
      if (response.success) {
        alert('건의사항이 등록되었습니다');
        setDialogOpen(false);
        setFormData({ title: '', content: '' });
        fetchSuggestions();
        fetchMySuggestions();
      }
    } catch (error) {
      console.error('건의사항 등록 실패:', error);
      alert('건의사항 등록에 실패했습니다');
    }
  };

  const getStatusColor = (status) => {
    const colors = {
      SUBMITTED: 'default',
      IN_REVIEW: 'primary',
      COMPLETED: 'success',
      REJECTED: 'error',
    };
    return colors[status] || 'default';
  };

  const getStatusLabel = (status) => {
    const labels = {
      SUBMITTED: '접수',
      IN_REVIEW: '검토중',
      COMPLETED: '완료',
      REJECTED: '반려',
    };
    return labels[status] || status;
  };

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('ko-KR');
  };

  const renderSuggestions = (list) => (
    <Grid container spacing={3}>
      {list.length === 0 ? (
        <Grid item xs={12}>
          <Paper sx={{ p: 3, textAlign: 'center' }}>
            <Typography color="text.secondary">건의사항이 없습니다</Typography>
          </Paper>
        </Grid>
      ) : (
        list.map((suggestion) => (
          <Grid item xs={12} md={6} key={suggestion.id}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                  <Typography variant="h6">{suggestion.title}</Typography>
                  <Chip
                    label={getStatusLabel(suggestion.status)}
                    color={getStatusColor(suggestion.status)}
                    size="small"
                  />
                </Box>
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  {suggestion.content}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {formatDate(suggestion.createdAt)}
                </Typography>
                
                {suggestion.adminReply && (
                  <Box sx={{ mt: 2, p: 2, bgcolor: 'grey.100', borderRadius: 1 }}>
                    <Typography variant="caption" fontWeight="bold" display="block">
                      관리자 답변:
                    </Typography>
                    <Typography variant="body2">
                      {suggestion.adminReply}
                    </Typography>
                  </Box>
                )}
              </CardContent>
            </Card>
          </Grid>
        ))
      )}
    </Grid>
  );

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 3 }}>
        <Typography variant="h4">익명 건의함</Typography>
        <Button
          variant="contained"
          startIcon={<Add />}
          onClick={() => setDialogOpen(true)}
        >
          건의하기
        </Button>
      </Box>

      <Paper sx={{ mb: 3 }}>
        <Tabs value={tabValue} onChange={(e, v) => setTabValue(v)}>
          <Tab label="전체 건의사항" />
          <Tab label="내 건의사항" />
        </Tabs>
      </Paper>

      {tabValue === 0 && renderSuggestions(suggestions)}
      {tabValue === 1 && renderSuggestions(mySuggestions)}

      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>
          <Box sx={{ display: 'flex', alignItems: 'center' }}>
            <Feedback sx={{ mr: 1 }} />
            익명 건의하기
          </Box>
        </DialogTitle>
        <DialogContent>
          <Box sx={{ mb: 2, p: 2, bgcolor: 'info.light', borderRadius: 1 }}>
            <Typography variant="body2">
              💡 익명으로 처리되므로 작성자 정보는 노출되지 않습니다
            </Typography>
          </Box>
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
            rows={6}
            value={formData.content}
            onChange={(e) => setFormData({ ...formData, content: e.target.value })}
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

export default SuggestionPage;