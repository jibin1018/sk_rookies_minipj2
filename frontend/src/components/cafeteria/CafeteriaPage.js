import React, { useState, useEffect } from 'react';
import {
  Container,
  Paper,
  Typography,
  Button,
  Box,
  Card,
  CardContent,
  Grid,
  Rating,
  TextField,
  IconButton,
} from '@mui/material';
import { Restaurant, Star, NavigateBefore, NavigateNext } from '@mui/icons-material';
import { useAuth } from '../../contexts/AuthContext';
import cafeteriaService from '../../services/cafeteriaService';

const CafeteriaPage = () => {
  const { user } = useAuth();
  const [currentDate, setCurrentDate] = useState(new Date());
  const [menus, setMenus] = useState([]);
  const [reviews, setReviews] = useState({});

  useEffect(() => {
    fetchMenus();
  }, [currentDate]);

  const fetchMenus = async () => {
    try {
      const dateStr = currentDate.toISOString().split('T')[0];
      const response = await cafeteriaService.getMenusByDate(dateStr);
      if (response.success) {
        setMenus(response.data);
        
        // 각 메뉴의 평점 조회
        response.data.forEach(async (menu) => {
          const ratingResponse = await cafeteriaService.getAverageRating(menu.id);
          if (ratingResponse.success) {
            setReviews(prev => ({
              ...prev,
              [menu.id]: ratingResponse.data,
            }));
          }
        });
      }
    } catch (error) {
      console.error('식단 조회 실패:', error);
    }
  };

  const handlePrevDay = () => {
    setCurrentDate(new Date(currentDate.setDate(currentDate.getDate() - 1)));
  };

  const handleNextDay = () => {
    setCurrentDate(new Date(currentDate.setDate(currentDate.getDate() + 1)));
  };

  const handleToday = () => {
    setCurrentDate(new Date());
  };

  const handleReview = async (menuId, rating) => {
    try {
      const response = await cafeteriaService.createReview(menuId, {
        rating,
        comment: '',
      });
      
      if (response.success) {
        alert('평가가 등록되었습니다');
        fetchMenus();
      }
    } catch (error) {
      console.error('평가 등록 실패:', error);
      alert(error.response?.data?.message || '평가 등록에 실패했습니다');
    }
  };

  const getMealTypeLabel = (mealType) => {
    const labels = {
      '조식': '🌅 조식',
      '중식': '🍽️ 중식',
      '석식': '🌙 석식',
    };
    return labels[mealType] || mealType;
  };

  const formatDate = (date) => {
    return date.toLocaleDateString('ko-KR', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      weekday: 'long',
    });
  };

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      <Typography variant="h4" gutterBottom>
        <Restaurant sx={{ mr: 1, verticalAlign: 'middle' }} />
        구내식당 식단표
      </Typography>

      <Paper sx={{ p: 3, mb: 3 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <IconButton onClick={handlePrevDay}>
            <NavigateBefore />
          </IconButton>
          
          <Box sx={{ textAlign: 'center' }}>
            <Typography variant="h6">{formatDate(currentDate)}</Typography>
            <Button size="small" onClick={handleToday}>
              오늘
            </Button>
          </Box>
          
          <IconButton onClick={handleNextDay}>
            <NavigateNext />
          </IconButton>
        </Box>
      </Paper>

      <Grid container spacing={3}>
        {menus.length === 0 ? (
          <Grid item xs={12}>
            <Paper sx={{ p: 3, textAlign: 'center' }}>
              <Typography color="text.secondary">
                등록된 식단이 없습니다
              </Typography>
            </Paper>
          </Grid>
        ) : (
          menus.map((menu) => (
            <Grid item xs={12} md={4} key={menu.id}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    {getMealTypeLabel(menu.mealType)}
                  </Typography>
                  
                  <Box sx={{ my: 2 }}>
                    {menu.menuItems.split(',').map((item, index) => (
                      <Typography key={index} variant="body2">
                        • {item.trim()}
                      </Typography>
                    ))}
                  </Box>

                  {menu.calories && (
                    <Typography variant="caption" color="text.secondary" display="block">
                      칼로리: {menu.calories} kcal
                    </Typography>
                  )}

                  <Box sx={{ mt: 2, pt: 2, borderTop: '1px solid #e0e0e0' }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Star sx={{ color: 'gold' }} />
                      <Typography variant="body2">
                        평점: {reviews[menu.id]?.toFixed(1) || '없음'}
                      </Typography>
                    </Box>
                    
                    <Box sx={{ mt: 1 }}>
                      <Typography variant="caption" display="block" gutterBottom>
                        이 식단 평가하기:
                      </Typography>
                      <Rating
                        onChange={(e, value) => handleReview(menu.id, value)}
                        size="small"
                      />
                    </Box>
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