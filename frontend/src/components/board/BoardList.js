import { useState, useEffect } from "react";
import {
  Container,
  Button,
  Typography,
  Box,
  Chip,
  TextField,
  InputAdornment,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Divider,
} from "@mui/material";
import { Search, Add, Visibility, ChatBubbleOutline } from "@mui/icons-material";
import { useNavigate } from "react-router-dom";
import boardService from "../../services/boardService";

const BoardList = () => {
  const [boards, setBoards] = useState([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(0);
  const [totalPages, setTotalPages] = useState(0);
  const [searchKeyword, setSearchKeyword] = useState("");
  const [category, setCategory] = useState("ALL");

  const navigate = useNavigate();

  useEffect(() => {
    fetchBoards();
  }, [page, category]);

  const fetchBoards = async () => {
    try {
      setLoading(true);
      const response = await boardService.getBoards(page, 10);

      if (response.success) {
        let list = response.data.content;
        if (category !== "ALL") {
          list = list.filter((b) => b.category === category);
        }
        setBoards(list);
        setTotalPages(response.data.totalPages);
      }
    } catch (error) {
      console.error("게시글 목록 조회 실패:", error);
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
      console.error("검색 실패:", error);
    } finally {
      setLoading(false);
    }
  };

  const getCategoryLabel = (c) =>
    ({ NOTICE: "공지사항", FREE: "자유게시판", EVENT: "경조사", CLUB: "동호회", MARKET: "중고거래" }[c] || c);

  const formatDate = (d) => new Date(d).toLocaleDateString("ko-KR");

  return (
    <Container maxWidth="lg" sx={{ mt: 2, mb: 4 }}>
      <Typography variant="h4" sx={{ mb: 3 }}>사내 게시판</Typography>

      <Box
        sx={{
          display: "grid",
          gridTemplateColumns: "160px 1fr auto",
          gap: 2,
          alignItems: "center",
          mb: 4,
        }}
      >
        {/* 카테고리 */}
        <FormControl fullWidth>
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

        {/* 검색 */}
        <TextField
          fullWidth
          placeholder="검색"
          value={searchKeyword}
          onChange={(e) => setSearchKeyword(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleSearch()}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <Search />
              </InputAdornment>
            ),
          }}
        />

        {/* 버튼 영역 */}
        <Box sx={{ display: "flex", gap: 1 }}>
          <Button
            variant="contained"
            onClick={handleSearch}
            sx={{ minWidth: 80, whiteSpace: "nowrap" }}
          >
            검색
          </Button>
          <Button
            variant="contained"
            startIcon={<Add />}
            onClick={() => navigate("/boards/new")}
            sx={{ minWidth: 100, whiteSpace: "nowrap" }}
          >
            글쓰기
          </Button>
        </Box>
      </Box>



      {loading ? (
        <Typography align="center">로딩 중...</Typography>
      ) : boards.length === 0 ? (
        <Typography align="center">게시글이 없습니다</Typography>
      ) : (
        boards.map((board, i) => (
          <Box key={board.id}>
            <Box sx={{ p: 2, cursor: "pointer" }} onClick={() => navigate(`/boards/${board.id}`)}>
              <Chip label={getCategoryLabel(board.category)} size="small" sx={{ mb: 1 }} />
              <Typography variant="h6">{board.title}</Typography>
              <Typography variant="body2">
                {board.authorName} · {formatDate(board.createdAt)} · 조회 {board.views}
                {board.commentCount > 0 && ` · 💬 ${board.commentCount}`}
              </Typography>
            </Box>
            {i < boards.length - 1 && <Divider />}
          </Box>
        ))
      )}
    </Container>
  );
};

export default BoardList;
