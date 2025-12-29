import api from './api';

const attendanceService = {
  // 출근
  checkIn: async () => {
    const response = await api.post('/attendance/check-in');
    return response.data;
  },

  // 퇴근
  checkOut: async () => {
    const response = await api.post('/attendance/check-out');
    return response.data;
  },

  // 내 근태 조회
  getMyAttendance: async (year, month) => {
    const response = await api.get('/attendance/my', {
      params: { year, month },
    });
    return response.data;
  },

  // 오늘 근태 조회
  getTodayAttendance: async () => {
    const response = await api.get('/attendance/today');
    return response.data;
  },

  // 관리자 전체 근태 조회 ← 이 메서드 추가!
  getAllAttendance: async (date) => {
    const response = await api.get('/attendance/admin/all', {
      params: { date },
    });
    return response.data;
  },
};

export default attendanceService;