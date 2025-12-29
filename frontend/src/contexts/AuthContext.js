import React, { createContext, useState, useContext, useEffect } from 'react';
import authService from '../services/authService';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const storedUser = authService.getCurrentUser();
    console.log('저장된 사용자:', storedUser); // 디버깅용
    if (storedUser) {
      setUser(storedUser);
    }
    setLoading(false);
  }, []);

  const login = async (employeeId, password) => {
    try {
      console.log('AuthContext - 로그인 요청:', employeeId); // 디버깅용
      const response = await authService.login(employeeId, password);
      console.log('AuthContext - 응답:', response); // 디버깅용
      
      if (response.success) {
        const userData = response.data;
        localStorage.setItem('token', userData.token);
        localStorage.setItem('user', JSON.stringify(userData));
        setUser(userData);
        console.log('AuthContext - 사용자 정보 저장 완료'); // 디버깅용
        return { success: true };
      }
      return { success: false, message: response.message };
    } catch (error) {
      console.error('AuthContext - 로그인 에러:', error); // 디버깅용
      return { 
        success: false, 
        message: error.response?.data?.message || '로그인에 실패했습니다' 
      };
    }
  };

  const logout = () => {
    authService.logout();
    setUser(null);
  };

  const value = {
    user,
    login,
    logout,
    loading,
    isAuthenticated: !!user,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};