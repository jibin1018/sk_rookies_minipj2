// src/services/employeeService.js

import api from './api';
import CryptoJS from 'crypto-js';

const employeeService = {
  getAllEmployees: async () => {
    const response = await api.get('/employees');
    return response.data;
  },

  getEmployee: async (id) => {
    const response = await api.get(`/employees/${id}`);
    return response.data;
  },

  createEmployee: async (employeeData) => {
    // 항상 SHA-256 해시
    const hashedPassword = CryptoJS.SHA256(employeeData.password).toString();

    const requestData = {
      ...employeeData,
      password: hashedPassword,
    };

    const response = await api.post('/employees', requestData);
    return response.data;
  },

  updateEmployee: async (id, employeeData) => {
    const response = await api.put(`/employees/${id}`, employeeData);
    return response.data;
  },

  deleteEmployee: async (id) => {
    const response = await api.delete(`/employees/${id}`);
    return response.data;
  },
};

export default employeeService;