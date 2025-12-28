import api from './api';

const scheduleService = {
  getTeamSchedules: async (teamId) => {
    const response = await api.get(`/teams/${teamId}/schedules`);
    return response.data;
  },

  getSchedulesByDateRange: async (teamId, start, end) => {
    const response = await api.get(`/teams/${teamId}/schedules/range`, {
      params: { start, end },
    });
    return response.data;
  },

  createSchedule: async (teamId, scheduleData) => {
    const response = await api.post(`/teams/${teamId}/schedules`, scheduleData);
    return response.data;
  },

  deleteSchedule: async (teamId, scheduleId) => {
    const response = await api.delete(`/teams/${teamId}/schedules/${scheduleId}`);
    return response.data;
  },
};

export default scheduleService;