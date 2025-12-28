import api from './api';

const departmentService = {
  getAllDepartments: async () => {
    const response = await api.get('/departments');
    return response.data;
  },

  getAllTeams: async () => {
    const response = await api.get('/teams');
    return response.data;
  },

  getTeamsByDepartment: async (departmentId) => {
    const response = await api.get(`/teams/department/${departmentId}`);
    return response.data;
  },
};

export default departmentService;