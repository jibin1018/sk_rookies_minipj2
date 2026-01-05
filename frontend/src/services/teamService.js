// src/services/teamService.js

import api from './api';

const teamService = {
  getAllTeams: async () => {
    const response = await api.get('/teams');
    return response.data;
  },
};

export default teamService;