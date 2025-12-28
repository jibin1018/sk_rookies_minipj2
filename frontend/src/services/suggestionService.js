import api from './api';

const suggestionService = {
  createSuggestion: async (suggestionData) => {
    const response = await api.post('/suggestions', suggestionData);
    return response.data;
  },

  getAllSuggestions: async (page = 0, size = 10) => {
    const response = await api.get('/suggestions', {
      params: { page, size },
    });
    return response.data;
  },

  getSuggestionsByStatus: async (status, page = 0, size = 10) => {
    const response = await api.get(`/suggestions/status/${status}`, {
      params: { page, size },
    });
    return response.data;
  },

  getMySuggestions: async () => {
    const response = await api.get('/suggestions/my');
    return response.data;
  },

  getSuggestion: async (id) => {
    const response = await api.get(`/suggestions/${id}`);
    return response.data;
  },

  updateStatus: async (id, status, reply = null) => {
    const response = await api.put(`/suggestions/${id}/status`, null, {
      params: { status, reply },
    });
    return response.data;
  },
};

export default suggestionService;