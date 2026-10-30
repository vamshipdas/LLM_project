# SOC Assistant frontend

The frontend reads its API URL from `VITE_API_BASE`. The local `.env` points to
`http://127.0.0.1:8000/api/v1`, matching the supplied backend runner.

```powershell
npm install
npm run dev
```

Use `.env.example` as the deployment template. Only variables prefixed with
`VITE_` are exposed to browser code; never put the NVIDIA API key here.
