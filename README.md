# NIDS Frontend (React)

This is a lightweight React frontend for the Smart OS-based Network Intrusion Detection System (NIDS) project. It provides a dashboard, live packet feed simulation, alerts, signature browser, ML insights chart, and audit logs.

Quick start

1. Install dependencies:

```powershell
cd "c:\Users\Dhyanesh Dwivedi\OneDrive\Desktop\OS_Project"
npm install
```

2. Run dev server:

```powershell
npm run dev
```

Notes
- This project uses a mock API in `src/mock/api.js`. Replace with real backend endpoints or WebSocket streams to connect to a running agent.
- Chart.js is used for a simple anomaly score chart under ML Insights.

Next steps
- Add real-time WebSocket connection to the OS agent.
- Implement authentication and secure channel (mTLS) to the agent.
- Wire up ML model outputs from a model server (TensorFlow/PyTorch or REST endpoint).
