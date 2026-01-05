import api from './api';

const fileService = {
  uploadFile: async (teamId, file, folderPath = null) => {
    const formData = new FormData();
    formData.append('file', file);
    if (folderPath) {
      formData.append('folderPath', folderPath);
    }

    const response = await api.post(`/teams/${teamId}/files`, formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },

  getTeamFiles: async (teamId, folderPath = null) => {
    const response = await api.get(`/teams/${teamId}/files`, {
      params: { folderPath },
    });
    return response.data;
  },

  downloadFile: async (fileId, path = null) => {
    const response = await api.get(`/files/${fileId}`, {
      params: { path },
      responseType: 'blob',
    });
    return response;
  },

  deleteFile: async (fileId) => {
    const response = await api.delete(`/files/${fileId}`);
    return response.data;
  },
};

export default fileService;