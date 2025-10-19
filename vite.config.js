import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { VitePWA } from "vite-plugin-pwa";
import mkcert from "vite-plugin-mkcert";

const basePath = "/signature-playground/"; // sesuai nama repo GitHub

export default defineConfig({
  base: basePath,
  plugins: [
    react(),
    mkcert(),
    VitePWA({
      registerType: "autoUpdate",
      injectRegister: "auto",
      manifest: {
        name: "Signature Playground v6",
        short_name: "Signature",
        description: "PKCS#1-compatible Signature Playground – Paylabs",
        theme_color: "#ffffffff",
        background_color: "#ffffff",
        display: "standalone",
        orientation: "portrait",

        // gunakan basePath di sini agar path manifest & icon benar
        start_url: basePath,
        scope: basePath,

        icons: [
          {
            src: `${basePath}icons/icon-192x192.png`,
            sizes: "192x192",
            type: "image/png",
          },
          {
            src: `${basePath}icons/icon-512x512.png`,
            sizes: "512x512",
            type: "image/png",
          },
          {
            src: `${basePath}icons/icon-512x512.png`,
            sizes: "512x512",
            type: "image/png",
            purpose: "maskable",
          },
        ],
      },
    }),
  ],
  server: {
    https: true,
    host: "localhost",
    port: 5173,
  },
});
