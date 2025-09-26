import axios from 'axios';

const API_BASE_URL = 'http://localhost:8080/api/v1';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 5000, // Giảm timeout từ 10s xuống 5s
});

// Alerts API
export const alertsAPI = {
  getAlerts: (limit = 10) => api.get(`/detections?limit=${limit}`), // Giảm default limit
  getAlertById: (id) => api.get(`/detections/${id}`),
  getAlertsPaginated: (page = 1, limit = 10) => api.get(`/detections?page=${page}&limit=${limit}`),
};

// Endpoints API
export const endpointsAPI = {
  getEndpoints: () => api.get('/endpoints'),
  getEndpointById: (id) => api.get(`/endpoints/${id}`),
};

// Process Tree API
export const processTreeAPI = {
  getProcessTree: (endpointId) => api.get(`/process_tree?endpoint_id=${endpointId}`),
  getSuspiciousProcesses: (endpointId) => api.get(`/process_tree/suspicious?endpoint_id=${endpointId}`),
  analyzeProcessTree: (endpointId) => api.get(`/process_tree/analyze?endpoint_id=${endpointId}`),
};

// Rules API
export const rulesAPI = {
  getRules: () => api.get('/rules'),
  updateRules: (rules) => api.post('/rules', { rules }),
};

// Stats API
export const statsAPI = {
  getStats: () => api.get('/stats'),
};

export default api;
