import React, { useState, useEffect } from 'react';
import {
  Container,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Button,
  Typography,
  Box,
  Chip,
  TextField,
  InputAdornment,
  Pagination,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
} from '@mui/material';
import { Search, Add } from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import boardService from '../../services/boardService';
import { useSecurityMode } from '../../contexts/SecurityModeContext';

const BoardList = () => {
  const [boards, setBoards] = useState([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(0);
  const [totalPages, setTotalPages] = useState(0);
  const [searchKeyword, setSearchKeyword] = useState('');
  const [category, setCategory] = useState('ALL');
  
  const navigate = useNavigate();
  const { isSecure } = useSecurityMode();

  useEffect(() => {
    fetchBoards();
  }, [page, category]);

  const fetchBoards = async () => {
    try {
      setLoading(true);
      const response = await boardService.getBoards(page, 10);
      
      if (response.success) {
        let boardList = response.data.content;
        
        // 카테고리 필터링
        if (category !== 'ALL') {
          boardList = boardList.filter(board => board.category === category);
        }
        
        setBoards(boardList);
        setTotalPages(response.data.totalPages);
      }
    } catch (error) {
      console.error('게시글 목록 조회 실패:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = async () => {
    if (!searchKeyword.trim()) {
      fetchBoards();
      return;
    }

    try {
      setLoading(true);
      const response = await boardService.searchBoards(searchKeyword, page, 10);
      
      if (response.success) {
        setBoards(response.data.content);
        setTotalPages(response.data.totalPages);
      }
    } catch (error) {
      console.error('검색 실패:', error);
    } finally {
      setLoading(false);
    }
  };

  const handlePageChange = (event, value) => {
    setPage(value - 1);
  };

  const getCategoryLabel = (category) => {
    const labels = {
      NOTICE: '공지사항',
      FREE: '자유게시판',
      EVENT: '경조사',
      CLUB: '동호회',
      MARKET: '중고거래',
    };
    return labels[category] || category;
  };

  const getCategoryColor = (category) => {
    const colors = {
      NOTICE: 'error',
      FREE: 'primary',
      EVENT: 'secondary',
      CLUB: 'success',
      MARKET: 'warning',
    };
    return colors[category] || 'default';
  };

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('ko-KR');
  };

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 3 }}>
        <Typography variant="h4">사내 게시판</Typography>
        <Button
          variant="contained"
          startIcon={<Add />}
          onClick={() => navigate('/boards/new')}
        >
          글쓰기
        </Button>
      </Box>

      {!isSecure && (
        <Box sx={{ mb: 2, p: 2, bgcolor: 'error.light', borderRadius: 1 }}>
          <Typography variant="body2" color="error.contrastText">
            ⚠️ 취약 모드: XSS 공격 및 SQL Injection이 가능합니다
          </Typography>
        </Box>
      )}

      <Paper sx={{ p: 3, mb: 3 }}>
        <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
          <FormControl sx={{ minWidth: 150 }}>
            <InputLabel>카테고리</InputLabel>
            <Select
              value={category}
              label="카테고리"
              onChange={(e) => setCategory(e.target.value)}
            >
              <MenuItem value="ALL">전체</MenuItem>
              <MenuItem value="NOTICE">공지사항</MenuItem>
              <MenuItem value="FREE">자유게시판</MenuItem>
              <MenuItem value="EVENT">경조사</MenuItem>
              <MenuItem value="CLUB">동호회</MenuItem>
              <MenuItem value="MARKET">중고거래</MenuItem>
            </Select>
          </FormControl>

          <TextField
            fullWidth
            placeholder="제목 또는 내용 검색"
            value={searchKeyword}
            onChange={(e) => setSearchKeyword(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <Search />
                </InputAdornment>
              ),
            }}
          />
          
          <Button variant="contained" onClick={handleSearch}>
            검색
          </Button>
        </Box>
      </Paper>

      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell width="80px" align="center">번호</TableCell>
              <TableCell width="120px" align="center">카테고리</TableCell>
              <TableCell>제목</TableCell>
              <TableCell width="120px" align="center">작성자</TableCell>
              <TableCell width="100px" align="center">조회수</TableCell>
              <TableCell width="120px" align="center">작성일</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={6} align="center">
                  로딩 중...
                </TableCell>
              </TableRow>
            ) : boards.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} align="center">
                  게시글이 없습니다
                </TableCell>
              </TableRow>
            ) : (
              boards.map((board) => (
                <TableRow
                  key={board.id}
                  hover
                  sx={{ cursor: 'pointer' }}
                  onClick={() => navigate(`/boards/${board.id}`)}
                >
                  <TableCell align="center">
                    {board.isNotice ? (
                      <Chip label="공지" color="error" size="small" />
                    ) : (
                      board.id
                    )}
                  </TableCell>
                  <TableCell align="center">
                    <Chip
                      label={getCategoryLabel(board.category)}
                      color={getCategoryColor(board.category)}
                      size="small"
                    />
                  </TableCell>
                  <TableCell>
                    {board.title}
                    {board.commentCount > 0 && (
                      <Chip
                        label={board.commentCount}
                        size="small"
                        sx={{ ml: 1 }}
                      />
                    )}
                  </TableCell>
                  <TableCell align="center">{board.authorName}</TableCell>
                  <TableCell align="center">{board.views}</TableCell>
                  <TableCell align="center">{formatDate(board.createdAt)}</TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </TableContainer>

      {totalPages > 0 && (
        <Box sx={{ display: 'flex', justifyContent: 'center', mt: 3 }}>
          <Pagination
            count={totalPages}
            page={page + 1}
            onChange={handlePageChange}
            color="primary"
          />
        </Box>
      )}
    </Container>
  );
};

export default BoardList;