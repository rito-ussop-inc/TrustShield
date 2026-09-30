/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        shield: {
          50: '#eef6ff',
          100: '#d9eaff',
          500: '#2563eb',
          600: '#1d4ed8',
          900: '#0f2447'
        }
      }
    }
  },
  plugins: []
};
