import api from './api';

const boardService = {
  getBoards: async (page = 0, size = 10) => {
    const response = await api.get('/boards', {
      params: { page, size },
    });
    return response.data;
  },

  getBoard: async (id) => {
    const response = await api.get(`/boards/${id}`);
    return response.data;
  },

  createBoard: async (boardData) => {
    const response = await api.post('/boards', boardData);
    return response.data;
  },

  updateBoard: async (id, boardData) => {
    const response = await api.put(`/boards/${id}`, boardData);
    return response.data;
  },

  deleteBoard: async (id) => {
    const response = await api.delete(`/boards/${id}`);
    return response.data;
  },

  searchBoards: async (keyword, page = 0, size = 10) => {
    const response = await api.get('/boards/search', {
      params: { keyword, page, size },
    });
    return response.data;
  },

  getComments: async (boardId) => {
    const response = await api.get(`/boards/${boardId}/comments`);
    return response.data;
  },

  createComment: async (boardId, content, parentId = null) => {
    const response = await api.post(`/boards/${boardId}/comments`, {
      content,
      parentId,
    });
    return response.data;
  },

  deleteComment: async (commentId) => {
    const response = await api.delete(`/boards/comments/${commentId}`);
    return response.data;
  },
};

export default boardService;