import axios from "axios";

const api = axios.create({
  baseURL: "/api",
  timeout: 15000,
  withCredentials: true,
  withXSRFToken: true,
  xsrfCookieName: "sentinelx_csrf",
  xsrfHeaderName: "X-CSRF-TOKEN",
  headers: {
    "X-Requested-With": "XMLHttpRequest",
  },
});

export default api;