/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        midnight: '#080B0E',
        'midnight-surface': '#0E1317',
        'sage-deep': '#16221D',
        'sage-border': '#263830',
        'sage-muted': '#7E9489',
        'acid-lime': '#D4F849',
        ink: '#ECF2EE',
        'amber-warn': '#F59E0B',
        'crimson-veto': '#F43F5E',
      },
      fontFamily: {
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'Liberation Mono', 'Courier New', 'monospace'],
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
      },
    },
  },
  plugins: [],
}
