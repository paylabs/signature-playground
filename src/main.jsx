import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App.jsx";
import "./index.css";

import { registerSW } from "virtual:pwa-register";

const updateSW = registerSW({
  onNeedRefresh() {
    if (confirm("Versi baru tersedia. Muat ulang aplikasi sekarang?")) {
      updateSW(true);
    }
  },
  onOfflineReady() {
    console.log("Aplikasi siap digunakan secara offline!");
  },
});

createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
