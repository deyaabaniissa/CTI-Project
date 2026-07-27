# Healthcare CTI SOC Dashboard

React + Vite frontend for the healthcare threat intelligence dashboard.

## Local Setup

1. Start the FastAPI backend from the project root.
2. Copy `.env.example` to `.env` if you need custom API or WebSocket URLs.
3. Run the frontend:

```bash
npm install
npm run dev
```

The dashboard expects:

- `VITE_API_URL` for login and health API calls.
- `VITE_WS_URL` for the live traffic WebSocket.
