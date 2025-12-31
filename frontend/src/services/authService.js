// src/services/authService.js

import api from './api';
import CryptoJS from 'crypto-js';

const authService = {
  login: async (employeeId, password) => {
    // 항상 SHA-256 해시 적용
    const hashedPassword = CryptoJS.SHA256(password).toString();
    
    console.log('로그인 시도:', employeeId);
    console.log('해시된 비밀번호:', hashedPassword);
    
    const response = await api.post('/auth/login', {
      employeeId,
      password: hashedPassword,
    });
    
    return response.data;
  },

  signup: async (userData) => {
    // 회원가입도 SHA-256 해시
    const hashedPassword = CryptoJS.SHA256(userData.password).toString();
    
    const response = await api.post('/auth/signup', {
      ...userData,
      password: hashedPassword
    });
    
    return response.data;
  },

  logout: () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    window.location.href = '/login';
  },

  getCurrentUser: () => {
    const userStr = localStorage.getItem('user');
    return userStr ? JSON.parse(userStr) : null;
  },

  isAuthenticated: () => {
    return !!localStorage.getItem('token');
  },
};

export default authService;