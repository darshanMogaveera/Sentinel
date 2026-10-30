import axios from 'axios';

export const API_BASE_URL = 'http://localhost:5000/api';

const client = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const getHealth = () => client.get('/health/status');
export const getDashboardStats = () => client.get('/dashboard/stats');
export const getDashboardActivity = (limit = 50) => client.get(`/dashboard/activity?limit=${limit}`);
export const getAlerts = (limit = 20) => client.get(`/alerts/?limit=${limit}`);
export const runPrediction = (packet: any) => client.post('/predictions/detect', packet);

// Live Monitoring Endpoints
export const getLiveStatus = () => client.get('/live/status');
export const getLiveDevices = () => client.get('/live/devices');
export const startLiveCapture = (interfaceName: string) => client.post('/live/start', { interface: interfaceName });
export const stopLiveCapture = () => client.post('/live/stop');
export const runLiveSimulation = (config: any) => client.post('/live/simulate', config);
export const getLiveRunStats = (runId: string) => client.get(`/live/run_stats/${runId}`);

export default client;
