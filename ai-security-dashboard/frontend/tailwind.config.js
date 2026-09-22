/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          black: '#0a0a0f',
          dark: '#12121a',
          gray: '#1e1e2a',
          accent: '#00ff88',
          warning: '#ffaa00',
          danger: '#ff4444',
          info: '#00ccff',
        }
      },
      fontFamily: {
        mono: ['"Fira Code"', 'monospace'],
      }
    },
  },
  plugins: [],
}
