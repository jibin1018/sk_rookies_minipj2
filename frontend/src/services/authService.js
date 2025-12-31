// src/services/authService.js

import api from './api';
import CryptoJS from 'crypto-js';

const authService = {
  login: async (employeeId, password) => {
    // 보안 모드 확인
    const securityMode = localStorage.getItem('securityMode') || 'secure';
    
    // Secure 모드일 때만 SHA-256 해시
    const finalPassword = securityMode === 'secure' 
      ? CryptoJS.SHA256(password).toString() 
      : password;
    
    console.log('로그인 모드:', securityMode);
    console.log('원본 비밀번호:', password);
    console.log('전송 비밀번호:', finalPassword);
    
    const response = await api.post('/auth/login', {
      employeeId,
      password: finalPassword,
    });
    
    return response.data;
  },

  signup: async (userData) => {
    const securityMode = localStorage.getItem('securityMode') || 'secure';
    
    const signupData = {
      ...userData,
      password: securityMode === 'secure' 
        ? CryptoJS.SHA256(userData.password).toString() 
        : userData.password
    };
    
    const response = await api.post('/auth/signup', signupData);
    return response.data;
  },

  setSecurityMode: (mode) => {
    localStorage.setItem('securityMode', mode);
  },

  getSecurityMode: () => {
    return localStorage.getItem('securityMode') || 'secure';
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