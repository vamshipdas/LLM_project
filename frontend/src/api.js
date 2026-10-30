const API_BASE =
  import.meta.env.VITE_API_BASE || "http://127.0.0.1:8123/api/v1";

const TOKEN_KEY = "soc_token";
export const AUTH_EXPIRED_EVENT = "auth:expired";

export function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

export function isLoggedIn() {
  return Boolean(getToken());
}

export class AuthError extends Error {
  constructor(message, status) {
    super(message);
    this.name = "AuthError";
    this.status = status;
  }
}

async function request(path, { method = "GET", body, isForm = false } = {}) {
  const headers = {};
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body && !isForm) headers["Content-Type"] = "application/json";

  let res;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      method,
      headers,
      body: isForm ? body : body ? JSON.stringify(body) : undefined,
    });
  } catch (err) {
    if (err.name === "TypeError" && (err.message || "").toLowerCase().includes("fetch")) {
      throw new Error(`Cannot connect to backend at ${API_BASE}. Ensure the backend server is running.`);
    }
    throw err;
  }

  if (res.status === 401) {
    clearToken();
    window.dispatchEvent(new Event(AUTH_EXPIRED_EVENT));
    throw new AuthError("Session expired. Please sign in again.", 401);
  }
  if (res.status === 403) {
    throw new AuthError("You do not have permission to do that.", 403);
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Request failed (${res.status})`);
  }
  if (res.status === 204) return null;
  return res.json();
}

/* --- Auth --- */
export async function login(username, password) {
  const data = await request("/auth/login", {
    method: "POST",
    body: { username, password },
  });
  setToken(data.access_token);
  return data;
}

export function logout() {
  clearToken();
}

export function fetchMe() {
  return request("/auth/me");
}

/* --- Chat --- */
export function newChat() {
  return request("/chat", { method: "POST" });
}

export function listChats() {
  return request("/chat/sessions");
}

export function getChatMessages(sessionId) {
  return request(`/chat/sessions/${encodeURIComponent(sessionId)}/messages`);
}

export function sendChatMessage(sessionId, message) {
  return request(`/chat/sessions/${encodeURIComponent(sessionId)}/message`, {
    method: "POST",
    body: { message },
  });
}

export async function streamChatMessage(sessionId, message, onEvent) {
  const res = await fetch(
    `${API_BASE}/chat/sessions/${encodeURIComponent(sessionId)}/stream`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${getToken()}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ message }),
    },
  );

  if (res.status === 401) {
    clearToken();
    window.dispatchEvent(new Event(AUTH_EXPIRED_EVENT));
    throw new AuthError("Session expired. Please sign in again.", 401);
  }
  if (!res.ok || !res.body) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Request failed (${res.status})`);
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let result = null;

  while (true) {
    const { value, done } = await reader.read();
    buffer += decoder.decode(value || new Uint8Array(), { stream: !done });
    const lines = buffer.split("\n");
    buffer = lines.pop() || "";
    for (const line of lines) {
      if (!line.trim()) continue;
      const event = JSON.parse(line);
      onEvent(event);
      if (event.type === "done") result = event;
    }
    if (done) break;
  }

  if (buffer.trim()) {
    const event = JSON.parse(buffer);
    onEvent(event);
    if (event.type === "done") result = event;
  }
  if (!result) throw new Error("The response stream ended unexpectedly.");
  return result;
}

export function archiveChat(sessionId, archived) {
  return request(`/chat/sessions/${encodeURIComponent(sessionId)}/archive`, {
    method: "PATCH",
    body: { archived },
  });
}

export function deleteChat(sessionId) {
  return request(`/chat/sessions/${encodeURIComponent(sessionId)}`, {
    method: "DELETE",
  });
}

/* --- Tickets --- */
export function listTickets() {
  return request("/tickets");
}

export function listOpenTickets() {
  return request("/tickets/open");
}

export function updateTicketStatus(ticketId, status) {
  return request(`/tickets/${encodeURIComponent(ticketId)}/status`, {
    method: "PATCH",
    body: { status },
  });
}

/* --- SOPs --- */
export function listSOPs() {
  return request("/sops");
}

export function getSOPChunks(sopId) {
  return request(`/sops/${encodeURIComponent(sopId)}/chunks`);
}

export function uploadSOP(formData) {
  return request("/sops/upload", { method: "POST", body: formData, isForm: true });
}

/* --- Log Analysis --- */
export function getLiveLogsStreamUrl() {
  const token = getToken() || "";
  return `${API_BASE}/logs/stream?token=${encodeURIComponent(token)}`;
}

export function stopLiveLogs() {
  return request("/logs/stop", { method: "POST" });
}

export function getLiveBuffer() {
  return request("/logs/live/buffer");
}

export function analyzeLiveBuffer() {
  return request("/logs/analyze/live", { method: "POST" });
}

export function uploadLogFile(file) {
  const formData = new FormData();
  formData.append("file", file);
  return request("/logs/upload", {
    method: "POST",
    body: formData,
    isForm: true,
  });
}

export function getUploadEvents(
  uploadId,
  { page = 1, pageSize = 100, level = "", severity = "", sortBySeverity = false, q = "" } = {}
) {
  const params = new URLSearchParams({
    page: String(page),
    page_size: String(pageSize),
  });
  if (level) params.append("level", level);
  if (severity) params.append("severity", severity);
  if (sortBySeverity) params.append("sort_by_severity", "true");
  if (q) params.append("q", q);
  return request(`/logs/uploads/${encodeURIComponent(uploadId)}/events?${params.toString()}`);
}

export function getSeverityRules() {
  return request("/logs/severity-rules");
}

export function analyzeUploadLog(uploadId) {
  return request(`/logs/analyze/${encodeURIComponent(uploadId)}`, {
    method: "POST",
  });
}

export function createTicketFromFinding(payload) {
  return request("/logs/create-ticket", {
    method: "POST",
    body: payload,
  });
}

/* --- Log Explainer Chatbot --- */
export function sendChatLogExplainer({ message, sessionId, context, detailLevel = "simple" }) {
  return request("/logs/chat", {
    method: "POST",
    body: {
      message,
      session_id: sessionId,
      context,
      detail_level: detailLevel,
    },
  });
}

export function getLogChatMessages(sessionId) {
  return request(`/logs/chat/sessions/${encodeURIComponent(sessionId)}/messages`);
}

export function clearLogChatMessages(sessionId) {
  return request(`/logs/chat/sessions/${encodeURIComponent(sessionId)}/clear`, {
    method: "POST",
  });
}

/* --- Threat Map & Geolocation --- */
export function getThreatMapOrigins(uploadId = null) {
  const url = uploadId
    ? `/threat-map/origins?upload_id=${encodeURIComponent(uploadId)}`
    : "/threat-map/origins";
  return request(url);
}

export function getThreatOriginDetail(ip, uploadId = null) {
  const url = uploadId
    ? `/threat-map/origins/${encodeURIComponent(ip)}?upload_id=${encodeURIComponent(uploadId)}`
    : `/threat-map/origins/${encodeURIComponent(ip)}`;
  return request(url);
}

export function getHomeLocation() {
  return request("/settings/home-location");
}

export function updateHomeLocation({ lat, lon, label }) {
  return request("/settings/home-location", {
    method: "PUT",
    body: { lat, lon, label },
  });
}

export function getThreatMapStreamUrl() {
  const token = getToken();
  return `${API_BASE}/threat-map/stream${token ? `?token=${encodeURIComponent(token)}` : ""}`;
}

/* --- Alert Detail & Intelligence --- */
export function getAlertSummary(alertType, alertId, mode = "simple") {
  return request(`/alerts/${encodeURIComponent(alertType)}/${encodeURIComponent(alertId)}/summary?mode=${encodeURIComponent(mode)}`);
}

export function updateAlertStatus(alertType, alertId, status) {
  return request(`/alerts/${encodeURIComponent(alertType)}/${encodeURIComponent(alertId)}/status`, {
    method: "PATCH",
    body: { status },
  });
}

/* --- Critical Alert Notifications --- */
export function getNotificationSettings() {
  return request("/notifications/settings");
}

export function updateNotificationSettings(payload) {
  return request("/notifications/settings", {
    method: "PUT",
    body: payload,
  });
}

export function sendTestNotification() {
  return request("/notifications/test", {
    method: "POST",
  });
}

export function getNotificationLogs(limit = 50) {
  return request(`/notifications/log?limit=${limit}`);
}

export function getAlertNotificationStatus(alertId) {
  return request(`/notifications/status/${encodeURIComponent(alertId)}`);
}

export function resendAlertNotification(alertId) {
  return request(`/notifications/resend/${encodeURIComponent(alertId)}`, {
    method: "POST",
  });
}




