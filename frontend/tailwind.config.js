/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        ink: {
          950: '#05070D',
          900: '#0B0F16',
          850: '#0E1420',
          800: '#10151E',
          700: '#1A2230',
        },
        mist: {
          100: '#F2F4F8',
          300: '#9BA4B2',
          500: '#687180',
        },
        risk: {
          low: '#34D399',
          medium: '#FBBF24',
          high: '#FB7185',
          critical: '#EF4444',
          unknown: '#94A3B8',
        },
        shield: {
          50: '#eef6ff',
          100: '#d9eaff',
          500: '#2563eb',
          600: '#1d4ed8',
          900: '#0f2447'
        }
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', '-apple-system', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', 'monospace'],
      },
      maxWidth: {
        shell: '80rem',
      },
    }
  },
  plugins: []
};
