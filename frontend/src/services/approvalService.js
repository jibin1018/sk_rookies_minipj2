import api from './api';

const approvalService = {
  createApproval: async (approvalData) => {
    const response = await api.post('/approvals', approvalData);
    return response.data;
  },

  getMyApprovals: async (page = 0, size = 10) => {
    const response = await api.get('/approvals/my', {
      params: { page, size },
    });
    return response.data;
  },

  getMyApprovalsByStatus: async (status, page = 0, size = 10) => {
    const response = await api.get(`/approvals/my/status/${status}`, {
      params: { page, size },
    });
    return response.data;
  },

  getPendingApprovals: async () => {
    const response = await api.get('/approvals/pending');
    return response.data;
  },

  getApproval: async (id) => {
    const response = await api.get(`/approvals/${id}`);
    return response.data;
  },

  processApproval: async (id, action, comment = '') => {
    const response = await api.post(`/approvals/${id}/process`, {
      action,
      comment,
    });
    return response.data;
  },

  cancelApproval: async (id) => {
    const response = await api.delete(`/approvals/${id}`);
    return response.data;
  },
};

export default approvalService;