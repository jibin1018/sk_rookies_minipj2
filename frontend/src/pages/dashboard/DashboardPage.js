"use client"
import { Container, Grid, Paper, Typography, Box, Card, CardContent } from "@mui/material"
import { Article, Schedule, Description, Feedback, TrendingUp } from "@mui/icons-material"
import { useAuth } from "../../contexts/AuthContext"

const DashboardPage = () => {
  const { user } = useAuth()

  const stats = [
    {
      title: "사내 게시판",
      value: "0",
      subtitle: "새 글",
      icon: <Article fontSize="large" />,
      color: "#3b82f6",
      bgColor: "#eff6ff",
    },
    {
      title: "팀 일정",
      value: "1",
      subtitle: "이번 주",
      icon: <Schedule fontSize="large" />,
      color: "#10b981",
      bgColor: "#f0fdf4",
    },
    {
      title: "결재 대기",
      value: "0",
      subtitle: "처리 필요",
      icon: <Description fontSize="large" />,
      color: "#f59e0b",
      bgColor: "#fffbeb",
    },
    {
      title: "건의사항",
      value: "2",
      subtitle: "진행중",
      icon: <Feedback fontSize="large" />,
      color: "#8b5cf6",
      bgColor: "#faf5ff",
    },
  ]

  return (
    <Container maxWidth="lg" sx={{ py: 1 }}>
      <Paper
        sx={{
          p: 4,
          mb: 4,
          backgroundColor: "#1a2332",
          color: "white",
          borderRadius: 2,
          boxShadow: "0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06)",
        }}
      >
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <TrendingUp sx={{ fontSize: 40, color: "white" }} />
          <Box>
            <Typography variant="h4" gutterBottom sx={{ mb: 1, fontWeight: 700, color: "white" }}>
              환영합니다, {user?.name}님
            </Typography>
            <Typography variant="body1" sx={{ color: "rgba(255, 255, 255, 0.9)" }}>
              {user?.departmentName || "-"} / {user?.teamName || "-"} · {user?.position || "-"} · {user?.role || "-"}
            </Typography>
          </Box>
        </Box>
      </Paper>
      {/* </CHANGE> */}

      <Grid container spacing={3} sx={{ mb: 4 }}>
        {stats.map((stat, index) => (
          <Grid item xs={12} sm={6} md={3} key={index}>
            <Card
              sx={{
                height: "100%",
                transition: "all 0.2s ease-in-out",
                "&:hover": {
                  transform: "translateY(-4px)",
                  boxShadow: "0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)",
                },
              }}
            >
              <CardContent sx={{ p: 3 }}>
                <Box sx={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", mb: 2 }}>
                  <Box>
                    <Typography color="text.secondary" variant="body2" gutterBottom sx={{ fontWeight: 500 }}>
                      {stat.title}
                    </Typography>
                    <Typography variant="h3" sx={{ fontWeight: 700, mb: 0.5 }}>
                      {stat.value}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {stat.subtitle}
                    </Typography>
                  </Box>
                  <Box
                    sx={{
                      p: 1.5,
                      borderRadius: 2,
                      backgroundColor: stat.bgColor,
                      color: stat.color,
                    }}
                  >
                    {stat.icon}
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3, height: "100%" }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 2 }}>
              <Article sx={{ color: "primary.main", fontSize: 28 }} />
              <Typography variant="h6" sx={{ fontWeight: 600 }}>
                최근 공지사항
              </Typography>
            </Box>
            <Box
              sx={{
                p: 3,
                backgroundColor: "#f9fafb",
                borderRadius: 2,
                textAlign: "center",
              }}
            >
              <Typography variant="body2" color="text.secondary">
                좌측 메뉴에서 사내 게시판을 확인하세요
              </Typography>
            </Box>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3, height: "100%" }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 2 }}>
              <Schedule sx={{ color: "success.main", fontSize: 28 }} />
              <Typography variant="h6" sx={{ fontWeight: 600 }}>
                이번 주 일정
              </Typography>
            </Box>
            <Box
              sx={{
                p: 3,
                backgroundColor: "#f9fafb",
                borderRadius: 2,
                textAlign: "center",
              }}
            >
              <Typography variant="body2" color="text.secondary">
                좌측 메뉴에서 팀 일정을 확인하세요
              </Typography>
            </Box>
          </Paper>
        </Grid>
      </Grid>
    </Container>
  )
}

export default DashboardPage

