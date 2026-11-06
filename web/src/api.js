// Thin client for the control API. The token lives in sessionStorage only:
// it survives a page reload in this tab but not a closed browser.
const KEY = 'oc_token';

export function getToken() {
  return sessionStorage.getItem(KEY) || '';
}

export function setToken(token) {
  if (token) sessionStorage.setItem(KEY, token);
  else sessionStorage.removeItem(KEY);
}

export async function api(method, path, body) {
  const headers = {};
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';

  const res = await fetch(`/api/v1${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `${res.status} ${res.statusText}`);
  return data;
}

const RANK = { viewer: 1, operator: 2, admin: 3 };
export function can(role, min) {
  return (RANK[role] || 0) >= RANK[min];
}
