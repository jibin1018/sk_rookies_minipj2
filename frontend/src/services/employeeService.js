import api from './api';

const employeeService = {
  // 관리자 전용 - 전체 사원 조회
  getAllEmployees: async () => {
    const response = await api.get('/employees');
    return response.data;
  },

  // 모든 사용자 - 결재자 선택용
  getApprovers: async () => {
    const response = await api.get('/employees/approvers');
    return response.data;
  },

  getEmployee: async (id) => {
    const response = await api.get(`/employees/${id}`);
    return response.data;
  },

  createEmployee: async (employeeData) => {
    const response = await api.post('/employees', employeeData);
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