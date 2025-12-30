"use client"

import { useState, useEffect } from "react"
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
} from "@mui/material"
import { Search, Add, Visibility, ChatBubbleOutline } from "@mui/icons-material"
import { useNavigate } from "react-router-dom"
import boardService from "../../services/boardService"
import { useSecurityMode } from "../../contexts/SecurityModeContext"

const BoardList = () => {
  const [boards, setBoards] = useState([])
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(0)
  const [totalPages, setTotalPages] = useState(0)
  const [searchKeyword, setSearchKeyword] = useState("")
  const [category, setCategory] = useState("ALL")

  const navigate = useNavigate()
  const { isSecure } = useSecurityMode()

  useEffect(() => {
    fetchBoards()
  }, [page, category])

  const fetchBoards = async () => {
    try {
      setLoading(true)
      const response = await boardService.getBoards(page, 10)

      if (response.success) {
        let boardList = response.data.content

        // 카테고리 필터링
        if (category !== "ALL") {
          boardList = boardList.filter((board) => board.category === category)
        }

        setBoards(boardList)
        setTotalPages(response.data.totalPages)
      }
    } catch (error) {
      console.error("게시글 목록 조회 실패:", error)
    } finally {
      setLoading(false)
    }
  }

  const handleSearch = async () => {
    if (!searchKeyword.trim()) {
      fetchBoards()
      return
    }

    try {
      setLoading(true)
      const response = await boardService.searchBoards(searchKeyword, page, 10)

      if (response.success) {
        setBoards(response.data.content)
        setTotalPages(response.data.totalPages)
      }
    } catch (error) {
      console.error("검색 실패:", error)
    } finally {
      setLoading(false)
    }
  }

  const handlePageChange = (event, value) => {
    setPage(value - 1)
  }

  const getCategoryLabel = (category) => {
    const labels = {
      NOTICE: "공지사항",
      FREE: "자유게시판",
      EVENT: "경조사",
      CLUB: "동호회",
      MARKET: "중고거래",
    }
    return labels[category] || category
  }

  const getCategoryColor = (category) => {
    const colors = {
      NOTICE: "error",
      FREE: "primary",
      EVENT: "secondary",
      CLUB: "success",
      MARKET: "warning",
    }
    return colors[category] || "default"
  }

  const formatDate = (dateString) => {
    const date = new Date(dateString)
    return date.toLocaleDateString("ko-KR")
  }

  return (
    <Container maxWidth="lg" sx={{ mt: 2, mb: 4 }}>
      <Box sx={{ mb: 5 }}>
        <Typography variant="h4" sx={{ mb: 1, fontWeight: 700, fontSize: "2.5rem" }}>
          사내 게시판
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ fontSize: "1.125rem" }}>
          팀 소식과 정보를 공유하세요
        </Typography>
      </Box>

      {!isSecure && (
        <Box sx={{ mb: 3, p: 2.5, bgcolor: "#fff4e6", borderRadius: 2, border: "1px solid #ffe4b3" }}>
          <Typography variant="body2" sx={{ color: "#d97706", fontSize: "1rem" }}>
            ⚠️ 취약 모드: XSS 공격 및 SQL Injection이 가능합니다
          </Typography>
        </Box>
      )}

      <Box
        sx={{
          display: "flex",
          gap: 2,
          mb: 4,
          alignItems: "center",
          p: 2.5,
          backgroundColor: "#fafafa",
          borderRadius: 2,
          border: "1px solid rgba(55, 53, 47, 0.09)",
        }}
      >
        <FormControl sx={{ minWidth: 160 }}>
          <InputLabel>카테고리</InputLabel>
          <Select value={category} label="카테고리" onChange={(e) => setCategory(e.target.value)}>
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
          onKeyPress={(e) => e.key === "Enter" && handleSearch()}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <Search />
              </InputAdornment>
            ),
          }}
        />

        <Button
          variant="contained"
          onClick={handleSearch}
          sx={{
            minWidth: "100px",
            whiteSpace: "nowrap",
            flexShrink: 0,
            height: "56px",
            bgcolor: "#37352f",
            color: "#ffffff",
            "&:hover": { bgcolor: "#2c2a27" },
          }}
        >
          검색
        </Button>

        <Button
          variant="contained"
          startIcon={<Add />}
          onClick={() => navigate("/boards/new")}
          sx={{
            minWidth: "120px",
            whiteSpace: "nowrap",
            flexShrink: 0,
            height: "56px",
            bgcolor: "#37352f",
            color: "#ffffff",
            "&:hover": { bgcolor: "#2c2a27" },
          }}
        >
          글쓰기
        </Button>
      </Box>

      <Box sx={{ mb: 4 }}>
        {loading ? (
          <Box sx={{ p: 6, textAlign: "center", color: "text.secondary" }}>
            <Typography sx={{ fontSize: "1.125rem" }}>로딩 중...</Typography>
          </Box>
        ) : boards.length === 0 ? (
          <Box sx={{ p: 6, textAlign: "center", color: "text.secondary" }}>
            <Typography sx={{ fontSize: "1.125rem" }}>게시글이 없습니다</Typography>
          </Box>
        ) : (
          boards.map((board, index) => (
            <Box key={board.id}>
              <Box
                onClick={() => navigate(`/boards/${board.id}`)}
                sx={{
                  p: 3,
                  cursor: "pointer",
                  transition: "all 0.2s",
                  borderRadius: 1,
                  "&:hover": {
                    backgroundColor: "rgba(55, 53, 47, 0.03)",
                  },
                }}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 1.5 }}>
                  <Chip
                    label={getCategoryLabel(board.category)}
                    size="small"
                    sx={{
                      height: "24px",
                      fontSize: "0.875rem",
                      fontWeight: 500,
                      backgroundColor: board.category === "NOTICE" ? "#fef2f2" : "rgba(15, 98, 254, 0.08)",
                      color: board.category === "NOTICE" ? "#dc2626" : "#0f62fe",
                      border: "none",
                    }}
                  />
                  {board.isNotice && (
                    <Chip
                      label="공지"
                      size="small"
                      sx={{
                        height: "24px",
                        backgroundColor: "#fef2f2",
                        color: "#dc2626",
                        fontWeight: 600,
                      }}
                    />
                  )}
                </Box>

                <Typography
                  variant="h6"
                  sx={{
                    mb: 1,
                    fontWeight: 600,
                    fontSize: "1.25rem",
                    color: "#37352f",
                  }}
                >
                  {board.title}
                </Typography>

                <Box sx={{ display: "flex", alignItems: "center", gap: 2.5, color: "text.secondary" }}>
                  <Typography variant="body2" sx={{ fontSize: "0.9375rem" }}>
                    {board.authorName}
                  </Typography>
                  <Typography variant="body2" sx={{ fontSize: "0.9375rem" }}>
                    {formatDate(board.createdAt)}
                  </Typography>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                    <Visibility sx={{ fontSize: "1.125rem" }} />
                    <Typography variant="body2" sx={{ fontSize: "0.9375rem" }}>
                      {board.views}
                    </Typography>
                  </Box>
                  {board.commentCount > 0 && (
                    <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                      <ChatBubbleOutline sx={{ fontSize: "1.125rem" }} />
                      <Typography variant="body2" sx={{ fontSize: "0.9375rem" }}>
                        {board.commentCount}
                      </Typography>
                    </Box>
                  )}
                </Box>
              </Box>
              {index < boards.length - 1 && <Divider />}
            </Box>
          ))
        )}
      </Box>

      {totalPages > 0 && (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 4 }}>
          <Box sx={{ display: "flex", gap: 1 }}>
            {Array.from({ length: totalPages }, (_, i) => (
              <Button
                key={i}
                variant={page === i ? "contained" : "outlined"}
                onClick={() => setPage(i)}
                sx={{
                  minWidth: "40px",
                  height: "40px",
                  p: 1,
                  ...(page === i && {
                    bgcolor: "#37352f",
                    color: "#ffffff",
                    "&:hover": { bgcolor: "#2c2a27" },
                  }),
                  ...(page !== i && {
                    borderColor: "rgba(55, 53, 47, 0.16)",
                    color: "#37352f",
                    "&:hover": {
                      borderColor: "#37352f",
                      bgcolor: "rgba(55, 53, 47, 0.03)",
                    },
                  }),
                }}
              >
                {i + 1}
              </Button>
            ))}
          </Box>
        </Box>
      )}
    </Container>
  )
}

export default BoardList
