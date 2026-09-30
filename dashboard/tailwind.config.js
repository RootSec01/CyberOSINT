/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        ink: {
          900: "#0A0E14",
          800: "#0F151E",
          700: "#141B26",
          600: "#1C2634",
          500: "#273343",
        },
        edge: "#2A3646",
        mist: {
          300: "#8595AB",
          200: "#B4C0D0",
          100: "#E2E8F0",
        },
        signal: {
          DEFAULT: "#38E8C4",
          dim: "#1F9E86",
        },
        alert: {
          crit: "#F87171",
          high: "#FB923C",
          med: "#FBBF24",
          low: "#38BDF8",
        },
      },
      fontFamily: {
        display: ["Space Grotesk", "system-ui", "sans-serif"],
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "monospace"],
      },
      boxShadow: {
        panel: "0 1px 0 0 rgba(255,255,255,0.03) inset, 0 8px 30px -12px rgba(0,0,0,0.6)",
        glow: "0 0 24px -4px rgba(56,232,196,0.35)",
      },
    },
  },
  plugins: [],
};
