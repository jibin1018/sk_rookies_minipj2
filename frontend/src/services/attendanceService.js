import api from './api';

const attendanceService = {
  // 현재 시간으로 출근
  checkIn: async () => {
    const response = await api.post('/attendance/check-in', {});
    return response.data;
  },

  // 현재 시간으로 퇴근
  checkOut: async () => {
    const response = await api.post('/attendance/check-out', {});
    return response.data;
  },

  // 내 근태 조회
  getMyAttendances: async (startDate, endDate) => {
    const response = await api.get('/attendance/my', {
      params: { startDate, endDate },
    });
    return response.data;
  },

  // 팀 근태 조회 (팀장/관리자용)
  getTeamAttendances: async (teamId, date) => {
    const response = await api.get(`/attendance/team/${teamId}`, {
      params: { date },
    });
    return response.data;
  },
};

export default attendanceService;