import axios from 'axios';

const API_BASE_URL = '/api/v1';

// Create axios instance
const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Metrics service
export const metricsService = {
  getCurrent: async () => {
    const response = await apiClient.get('/metrics/current');
    return response.data;
  },
  
  getHistory: async (hours = 24, limit = 100) => {
    const response = await apiClient.get('/metrics/history', {
      params: { hours, limit }
    });
    return response.data;
  },
  
  getSummary: async () => {
    const response = await apiClient.get('/metrics/summary');
    return response.data;
  },
};

// Threats service
export const threatsService = {
  getAll: async (limit = 50, severity = null) => {
    const response = await apiClient.get('/threats/', {
      params: { limit, severity }
    });
    return response.data;
  },
  
  getCritical: async (limit = 20) => {
    const response = await apiClient.get('/threats/critical', { params: { limit } });
    return response.data;
  },
  
  getRecent: async (limit = 10) => {
    const response = await apiClient.get('/threats/recent', { params: { limit } });
    return response.data;
  },
  
  getStats: async () => {
    const response = await apiClient.get('/threats/stats');
    return response.data;
  },
};

// Skills service
export const skillsService = {
  getAll: async (category = null) => {
    const response = await apiClient.get('/skills/', {
      params: { category }
    });
    return response.data;
  },
  
  getCategories: async () => {
    const response = await apiClient.get('/skills/categories');
    return response.data;
  },
  
  getStats: async () => {
    const response = await apiClient.get('/skills/stats');
    return response.data;
  },
  
  create: async (skillData) => {
    const response = await apiClient.post('/skills/', skillData);
    return response.data;
  },
};

// Health check
export const healthCheck = async () => {
  const response = await apiClient.get('/health');
  return response.data;
};

export default apiClient;
