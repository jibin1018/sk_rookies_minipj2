import React, { useState, useEffect } from 'react';
import {
  Container,
  Paper,
  Typography,
  Box,
  Grid,
  Card,
  CardContent,
  IconButton,
  Chip,
} from '@mui/material';
import { ChevronLeft, ChevronRight, Restaurant } from '@mui/icons-material';
import cafeteriaService from '../../services/cafeteriaService';

const CafeteriaPage = () => {
  const [selectedDate, setSelectedDate] = useState(new Date());
  const [menus, setMenus] = useState([]);

  useEffect(() => {
    fetchMenus();
  }, [selectedDate]);

  const fetchMenus = async () => {
    try {
      const dateStr = selectedDate.toISOString().split('T')[0];
      console.log('식단 조회 날짜:', dateStr);
      
      const response = await cafeteriaService.getMenusByDate(dateStr);
      console.log('식단 응답:', response);
      
      if (response.success) {
        // 중식(점심)이 먼저 오도록 정렬
        const sortedMenus = response.data.sort((a, b) => {
          if (a.mealType === '중식') return -1;
          if (b.mealType === '중식') return 1;
          return 0;
        });
        setMenus(sortedMenus);
      }
    } catch (error) {
      console.error('식단 조회 실패:', error);
    }
  };

  const handlePrevDay = () => {
    const newDate = new Date(selectedDate);
    newDate.setDate(newDate.getDate() - 1);
    setSelectedDate(newDate);
  };

  const handleNextDay = () => {
    const newDate = new Date(selectedDate);
    newDate.setDate(newDate.getDate() + 1);
    setSelectedDate(newDate);
  };

  const handleToday = () => {
    setSelectedDate(new Date());
  };

  const formatDate = (date) => {
    return date.toLocaleDateString('ko-KR', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      weekday: 'long'
    });
  };

  const getMealTypeLabel = (mealType) => {
    const labels = {
      '중식': '점심',
      '석식': '저녁',
    };
    return labels[mealType] || mealType;
  };

  const getMealTypeColor = (mealType) => {
    const colors = {
      '중식': 'primary',
      '석식': 'secondary',
    };
    return colors[mealType] || 'default';
  };

  return (
    <Container maxWidth="md" sx={{ mt: 4, mb: 4 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
        <Restaurant sx={{ fontSize: 40, mr: 2, color: 'primary.main' }} />
        <Typography variant="h4">구내식당 식단표</Typography>
      </Box>

      {/* 날짜 선택 */}
      <Paper sx={{ p: 2, mb: 3, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <IconButton onClick={handlePrevDay}>
          <ChevronLeft />
        </IconButton>
        
        <Box sx={{ mx: 3, textAlign: 'center', minWidth: 300 }}>
          <Typography variant="h6">
            {formatDate(selectedDate)}
          </Typography>
          <Chip 
            label="오늘" 
            size="small" 
            onClick={handleToday}
            sx={{ mt: 1, cursor: 'pointer' }}
          />
        </Box>
        
        <IconButton onClick={handleNextDay}>
          <ChevronRight />
        </IconButton>
      </Paper>

      {/* 식단 표시 - 세로 배치 */}
      <Grid container spacing={3}>
        {menus.length === 0 ? (
          <Grid item xs={12}>
            <Paper sx={{ p: 4, textAlign: 'center' }}>
              <Typography color="text.secondary">
                등록된 식단이 없습니다
              </Typography>
            </Paper>
          </Grid>
        ) : (
          menus.map((menu) => (
            <Grid item xs={12} key={menu.id}>
              <Card elevation={3}>
                <CardContent sx={{ p: 3 }}>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                    <Chip
                      label={getMealTypeLabel(menu.mealType)}
                      color={getMealTypeColor(menu.mealType)}
                      size="large"
                      sx={{ fontSize: '1.1rem', fontWeight: 'bold', px: 2, py: 2.5 }}
                    />
                    <Typography variant="h6" color="text.secondary" sx={{ fontWeight: 'bold' }}>
                      {menu.calories} kcal
                    </Typography>
                  </Box>
                  
                  <Box>
                    {menu.menuItems.split(',').map((item, index) => (
                      <Typography 
                        key={index} 
                        variant="h6"
                        sx={{ 
                          py: 1,
                          display: 'flex',
                          alignItems: 'center',
                          '&:before': {
                            content: '"•"',
                            mr: 2,
                            color: 'primary.main',
                            fontWeight: 'bold',
                            fontSize: '1.5rem'
                          }
                        }}
                      >
                        {item.trim()}
                      </Typography>
                    ))}
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          ))
        )}
      </Grid>
    </Container>
  );
};

export default CafeteriaPage;