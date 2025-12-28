import api from './api';

const cafeteriaService = {
  createMenu: async (menuData) => {
    const response = await api.post('/cafeteria/menus', menuData);
    return response.data;
  },

  getMenusByDate: async (date) => {
    const response = await api.get('/cafeteria/menus', {
      params: { date },
    });
    return response.data;
  },

  getMenusByDateRange: async (startDate, endDate) => {
    const response = await api.get('/cafeteria/menus/range', {
      params: { startDate, endDate },
    });
    return response.data;
  },

  updateMenu: async (id, menuData) => {
    const response = await api.put(`/cafeteria/menus/${id}`, menuData);
    return response.data;
  },

  deleteMenu: async (id) => {
    const response = await api.delete(`/cafeteria/menus/${id}`);
    return response.data;
  },

  createReview: async (menuId, reviewData) => {
    const response = await api.post(`/cafeteria/menus/${menuId}/reviews`, reviewData);
    return response.data;
  },

  getReviewsByMenu: async (menuId) => {
    const response = await api.get(`/cafeteria/menus/${menuId}/reviews`);
    return response.data;
  },

  getAverageRating: async (menuId) => {
    const response = await api.get(`/cafeteria/menus/${menuId}/rating`);
    return response.data;
  },
};

export default cafeteriaService;