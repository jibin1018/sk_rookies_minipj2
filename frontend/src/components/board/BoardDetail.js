import React, { useState, useEffect } from 'react';
import {
  Container,
  Paper,
  Typography,
  Box,
  Chip,
  Button,
  Divider,
  TextField,
  List,
  ListItem,
  ListItemText,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
} from '@mui/material';
import { Edit, Delete, Reply } from '@mui/icons-material';
import { useParams, useNavigate } from 'react-router-dom';
import boardService from '../../services/boardService';
import { useAuth } from '../../contexts/AuthContext';

const BoardDetail = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const { user } = useAuth();

  const [board, setBoard] = useState(null);
  const [comments, setComments] = useState([]);
  const [commentContent, setCommentContent] = useState('');
  const [replyTo, setReplyTo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);

  useEffect(() => {
    fetchBoard();
    fetchComments();
  }, [id]);

  const fetchBoard = async () => {
    try {
      const response = await boardService.getBoard(id);
      if (response.success) {
        setBoard(response.data);
      }
    } catch (error) {
      console.error('게시글 조회 실패:', error);
      alert('게시글을 불러올 수 없습니다');
      navigate('/boards');
    } finally {
      setLoading(false);
    }
  };

  const fetchComments = async () => {
    try {
      const response = await boardService.getComments(id);
      if (response.success) {
        setComments(response.data);
      }
    } catch (error) {
      console.error('댓글 조회 실패:', error);
    }
  };

  const handleDelete = async () => {
    try {
      const response = await boardService.deleteBoard(id);
      if (response.success) {
        alert('게시글이 삭제되었습니다');
        navigate('/boards');
      }
    } catch (error) {
      console.error('삭제 실패:', error);
      alert(error.response?.data?.message || '삭제에 실패했습니다');
    }
  };

  const handleCommentSubmit = async () => {
    if (!commentContent.trim()) {
      alert('댓글 내용을 입력하세요');
      return;
    }

    try {
      const response = await boardService.createComment(
        id,
        commentContent,
        replyTo
      );

      if (response.success) {
        setCommentContent('');
        setReplyTo(null);
        fetchComments();
      }
    } catch (error) {
      console.error('댓글 작성 실패:', error);
      alert('댓글 작성에 실패했습니다');
    }
  };

  const handleCommentDelete = async (commentId) => {
    if (!window.confirm('댓글을 삭제하시겠습니까?')) return;

    try {
      const response = await boardService.deleteComment(commentId);
      if (response.success) {
        fetchComments();
      }
    } catch (error) {
      console.error('댓글 삭제 실패:', error);
      alert(error.response?.data?.message || '댓글 삭제에 실패했습니다');
    }
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

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleString('ko-KR');
  };

  const renderComment = (comment, depth = 0) => (
    <Box key={comment.id} sx={{ ml: depth * 4 }}>
      <ListItem
        sx={{
          border: '1px solid #e0e0e0',
          borderRadius: 1,
          mb: 1,
          bgcolor: depth > 0 ? '#f5f5f5' : 'white',
        }}
      >
        <ListItemText
          primary={
            <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
              <Typography variant="body2" fontWeight="bold">
                {comment.authorName}
              </Typography>
              <Box>
                {depth === 0 && (
                  <IconButton size="small" onClick={() => setReplyTo(comment.id)}>
                    <Reply fontSize="small" />
                  </IconButton>
                )}
                {user?.id === comment.authorId && (
                  <IconButton
                    size="small"
                    onClick={() => handleCommentDelete(comment.id)}
                  >
                    <Delete fontSize="small" />
                  </IconButton>
                )}
              </Box>
            </Box>
          }
          secondary={
            <>
              <Typography
                variant="body2"
                sx={{ mt: 1 }}
                dangerouslySetInnerHTML={{ __html: comment.content }}
              />
              <Typography variant="caption" color="text.secondary">
                {formatDate(comment.createdAt)}
              </Typography>
            </>
          }
        />
      </ListItem>
      {comment.replies &&
        comment.replies.map((reply) => renderComment(reply, depth + 1))}
    </Box>
  );

  if (loading) {
    return (
      <Container maxWidth="lg" sx={{ mt: 4 }}>
        <Typography>로딩 중...</Typography>
      </Container>
    );
  }

  if (!board) return null;

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      <Paper sx={{ p: 4 }}>
        <Box sx={{ mb: 2 }}>
          <Chip label={getCategoryLabel(board.category)} color="primary" />
          {board.isNotice && (
            <Chip label="공지" color="error" sx={{ ml: 1 }} />
          )}
        </Box>

        <Typography variant="h4" gutterBottom>
          {board.title}
        </Typography>

        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
          <Box>
            <Typography variant="body2" color="text.secondary">
              작성자: {board.authorName}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              작성일: {formatDate(board.createdAt)}
            </Typography>
          </Box>
          <Typography variant="body2" color="text.secondary">
            조회수: {board.views}
          </Typography>
        </Box>

        <Divider sx={{ my: 3 }} />

        <Typography
          variant="body1"
          sx={{ minHeight: 200, whiteSpace: 'pre-wrap' }}
          dangerouslySetInnerHTML={{ __html: board.content }}
        />

        <Divider sx={{ my: 3 }} />

        <Box sx={{ display: 'flex', gap: 1, justifyContent: 'flex-end' }}>
          <Button onClick={() => navigate('/boards')}>목록</Button>
          {user?.id === board.authorId && (
            <>
              <Button
                variant="outlined"
                startIcon={<Edit />}
                onClick={() => navigate(`/boards/${id}/edit`)}
              >
                수정
              </Button>
              <Button
                variant="outlined"
                color="error"
                startIcon={<Delete />}
                onClick={() => setDeleteDialogOpen(true)}
              >
                삭제
              </Button>
            </>
          )}
        </Box>

        <Divider sx={{ my: 3 }} />

        <Typography variant="h6" gutterBottom>
          댓글 ({comments.length})
        </Typography>

        <List>{comments.map((c) => renderComment(c))}</List>

        <Box sx={{ mt: 3 }}>
          {replyTo && (
            <Box sx={{ mb: 1, p: 1, bgcolor: 'info.light', borderRadius: 1 }}>
              <Typography variant="caption">
                답글 작성 중…
                <Button size="small" onClick={() => setReplyTo(null)}>
                  취소
                </Button>
              </Typography>
            </Box>
          )}
          <TextField
            fullWidth
            multiline
            rows={3}
            placeholder="댓글을 입력하세요"
            value={commentContent}
            onChange={(e) => setCommentContent(e.target.value)}
          />
          <Box sx={{ mt: 1, display: 'flex', justifyContent: 'flex-end' }}>
            <Button variant="contained" onClick={handleCommentSubmit}>
              {replyTo ? '답글 작성' : '댓글 작성'}
            </Button>
          </Box>
        </Box>
      </Paper>

      <Dialog open={deleteDialogOpen} onClose={() => setDeleteDialogOpen(false)}>
        <DialogTitle>게시글 삭제</DialogTitle>
        <DialogContent>
          <Typography>정말 이 게시글을 삭제하시겠습니까?</Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteDialogOpen(false)}>취소</Button>
          <Button onClick={handleDelete} color="error">
            삭제
          </Button>
        </DialogActions>
      </Dialog>
    </Container>
  );
};

export default BoardDetail;
