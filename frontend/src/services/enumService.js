// src/services/enumService.js

import api from './api';

const enumService = {
  getPositions: async () => {
    const response = await api.get('/enums/positions');
    return response.data;
  },

  getRoles: async () => {
    const response = await api.get('/enums/roles');
    return response.data;
  },
};

export default enumService;