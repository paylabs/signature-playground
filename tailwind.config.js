/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx,ts,tsx}"],
  theme: { extend: {} },
  plugins: [
    function ({ addUtilities }) {
      addUtilities({
        /* mode gelap */
        ".dark-scroll": {
          "scrollbar-width": "thin",
          "scrollbar-color": "#4b5563 #111827", // thumb track (Firefox)
        },
        ".dark-scroll::-webkit-scrollbar": {
          width: "8px",
          height: "8px",
        },
        ".dark-scroll::-webkit-scrollbar-thumb": {
          "background-color": "#4b5563", // gray-700
          "border-radius": "8px",
        },
        ".dark-scroll::-webkit-scrollbar-thumb:hover": {
          "background-color": "#6b7280", // gray-500
        },
        ".dark-scroll::-webkit-scrollbar-track": {
          "background-color": "#111827", // gray-900
        },
      });
    },
  ],
};
