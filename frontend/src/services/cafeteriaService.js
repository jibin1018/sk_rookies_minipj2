import api from './api';

const cafeteriaService = {
  // 날짜별 식단 조회
  getMenusByDate: async (date) => {
    const response = await api.get('/cafeteria/menus', {
      params: { date },
    });
    return response.data;
  },

  // 주간 식단 조회
  getWeeklyMenus: async (startDate, endDate) => {
    const response = await api.get('/cafeteria/menus/weekly', {
      params: { startDate, endDate },
    });
    return response.data;
  },
};

export default cafeteriaService;