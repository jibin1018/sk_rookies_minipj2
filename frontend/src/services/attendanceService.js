import api from './api';

const attendanceService = {
  checkIn: async (checkInTime = null) => {
    const response = await api.post('/attendance/check-in', 
      checkInTime ? { checkIn: checkInTime } : {}
    );
    return response.data;
  },

  checkOut: async (checkOutTime = null) => {
    const response = await api.post('/attendance/check-out',
      checkOutTime ? { checkOut: checkOutTime } : {}
    );
    return response.data;
  },

  getMyAttendances: async (startDate, endDate) => {
    const response = await api.get('/attendance/my', {
      params: { startDate, endDate },
    });
    return response.data;
  },

  getTeamAttendances: async (teamId, date) => {
    const response = await api.get(`/attendance/team/${teamId}`, {
      params: { date },
    });
    return response.data;
  },
};

export default attendanceService;