/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        canvas: '#000000',
        panel: '#09090B',
        elevated: '#141417',
        hairline: '#1E1E22',
        ink: '#F4F6F8',
        muted: '#8E95A2',
        cobalt: '#2563EB',
        'cobalt-hover': '#1D4ED8',
        'cobalt-light': '#4D8BFF',
        danger: '#EF4444',
        warning: '#F59E0B',
      },
      fontFamily: {
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'Liberation Mono', 'Courier New', 'monospace'],
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
      },
    },
  },
  plugins: [],
}
