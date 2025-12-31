import React, { useState, useEffect } from 'react';
import {
  Container,
  Paper,
  Typography,
  TextField,
  Button,
  Box,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  FormControlLabel,
  Checkbox,
} from '@mui/material';
import { useNavigate, useParams } from 'react-router-dom';
import boardService from '../../services/boardService';
import { useAuth } from '../../contexts/AuthContext';

const BoardForm = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const { user } = useAuth();

  const [formData, setFormData] = useState({
    category: 'FREE',
    title: '',
    content: '',
    isNotice: false,
  });

  const [loading, setLoading] = useState(false);
  const isEditMode = !!id;

  useEffect(() => {
    if (isEditMode) {
      fetchBoard();
    }
  }, [id]);

  const fetchBoard = async () => {
    try {
      const response = await boardService.getBoard(id);
      if (response.success) {
        const board = response.data;
        setFormData({
          category: board.category,
          title: board.title,
          content: board.content,
          isNotice: board.isNotice,
        });
      }
    } catch (error) {
      console.error('게시글 조회 실패:', error);
      alert('게시글을 불러올 수 없습니다');
      navigate('/boards');
    }
  };

  const handleChange = (e) => {
    const { name, value, checked } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: name === 'isNotice' ? checked : value,
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!formData.title.trim() || !formData.content.trim()) {
      alert('제목과 내용을 입력하세요');
      return;
    }

    try {
      setLoading(true);

      const response = isEditMode
        ? await boardService.updateBoard(id, formData)
        : await boardService.createBoard(formData);

      if (response.success) {
        alert(isEditMode ? '게시글이 수정되었습니다' : '게시글이 작성되었습니다');
        navigate(`/boards/${response.data.id}`);
      }
    } catch (error) {
      console.error('저장 실패:', error);
      alert(error.response?.data?.message || '저장에 실패했습니다');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container maxWidth="md" sx={{ mt: 4, mb: 4 }}>
      <Paper sx={{ p: 4 }}>
        <Typography variant="h5" gutterBottom>
          {isEditMode ? '게시글 수정' : '게시글 작성'}
        </Typography>

        <Box component="form" onSubmit={handleSubmit}>
          <FormControl fullWidth sx={{ mb: 2 }}>
            <InputLabel>카테고리</InputLabel>
            <Select
              name="category"
              value={formData.category}
              label="카테고리"
              onChange={handleChange}
              required
            >
              <MenuItem value="NOTICE">공지사항</MenuItem>
              <MenuItem value="FREE">자유게시판</MenuItem>
              <MenuItem value="EVENT">경조사</MenuItem>
              <MenuItem value="CLUB">동호회</MenuItem>
              <MenuItem value="MARKET">중고거래</MenuItem>
            </Select>
          </FormControl>

          {(user?.role === 'ADMIN' || user?.role === 'MANAGER') && (
            <FormControlLabel
              control={
                <Checkbox
                  name="isNotice"
                  checked={formData.isNotice}
                  onChange={handleChange}
                />
              }
              label="공지사항으로 등록"
              sx={{ mb: 2 }}
            />
          )}

          <TextField
            fullWidth
            label="제목"
            name="title"
            value={formData.title}
            onChange={handleChange}
            required
            sx={{ mb: 2 }}
          />

          <TextField
            fullWidth
            label="내용"
            name="content"
            value={formData.content}
            onChange={handleChange}
            multiline
            rows={15}
            required
            sx={{ mb: 2 }}
          />

          <Box sx={{ display: 'flex', gap: 1, justifyContent: 'flex-end' }}>
            <Button onClick={() => navigate('/boards')}>취소</Button>
            <Button type="submit" variant="contained" disabled={loading}>
              {loading ? '저장 중...' : isEditMode ? '수정' : '작성'}
            </Button>
          </Box>
        </Box>
      </Paper>
    </Container>
  );
};

export default BoardForm;
