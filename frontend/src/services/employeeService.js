import api from './api';

const employeeService = {
  getCurrentEmployee: async () => {
    const response = await api.get('/employees/me');
    return response.data;
  },

  getAllEmployees: async () => {
    const response = await api.get('/employees');
    return response.data;
  },

  getEmployeesByTeam: async (teamId) => {
    const response = await api.get(`/employees/team/${teamId}`);
    return response.data;
  },
};

export default employeeService;