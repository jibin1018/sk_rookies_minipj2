import React, { useState, useEffect } from 'react';
import {
  Container,
  Grid,
  Paper,
  Typography,
  Box,
  Card,
  CardContent,
} from '@mui/material';
import {
  Article,
  Schedule,
  Description,
  Feedback,
} from '@mui/icons-material';
import { useAuth } from '../../contexts/AuthContext';

const DashboardPage = () => {
  const { user } = useAuth();

  const stats = [
    {
      title: '사내 게시판',
      value: '5',
      icon: <Article fontSize="large" />,
      color: '#1976d2',
    },
    {
      title: '팀 일정',
      value: '3',
      icon: <Schedule fontSize="large" />,
      color: '#2e7d32',
    },
    {
      title: '결재 대기',
      value: '2',
      icon: <Description fontSize="large" />,
      color: '#ed6c02',
    },
    {
      title: '건의사항',
      value: '1',
      icon: <Feedback fontSize="large" />,
      color: '#9c27b0',
    },
  ];

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      <Typography variant="h4" gutterBottom>
        대시보드
      </Typography>

      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          환영합니다, {user?.name}님!
        </Typography>
        <Typography variant="body2" color="text.secondary">
          부서: {user?.departmentName} | 팀: {user?.teamName} | 직급: {user?.position}
        </Typography>
      </Paper>

      <Grid container spacing={3}>
        {stats.map((stat, index) => (
          <Grid item xs={12} sm={6} md={3} key={index}>
            <Card>
              <CardContent>
                <Box
                  sx={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                  }}
                >
                  <Box>
                    <Typography color="text.secondary" gutterBottom>
                      {stat.title}
                    </Typography>
                    <Typography variant="h4">{stat.value}</Typography>
                  </Box>
                  <Box sx={{ color: stat.color }}>{stat.icon}</Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      <Grid container spacing={3} sx={{ mt: 2 }}>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              최근 공지사항
            </Typography>
            <Typography variant="body2" color="text.secondary">
              공지사항이 없습니다.
            </Typography>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              이번 주 일정
            </Typography>
            <Typography variant="body2" color="text.secondary">
              일정이 없습니다.
            </Typography>
          </Paper>
        </Grid>
      </Grid>
    </Container>
  );
};

export default DashboardPage;