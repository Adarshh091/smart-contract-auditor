/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        background: {
          DEFAULT: '#090d16',
          secondary: '#0f172a',
          card: '#111927',
          elevated: '#1a2234',
        },
        border: {
          subtle: '#1e293b',
          muted: '#2a374a',
          accent: '#3b82f6',
        },
        severity: {
          high: {
            DEFAULT: '#ef4444',
            bg: 'rgba(239, 68, 68, 0.12)',
            border: 'rgba(239, 68, 68, 0.3)',
            glow: 'rgba(239, 68, 68, 0.25)',
          },
          medium: {
            DEFAULT: '#f97316',
            bg: 'rgba(249, 115, 22, 0.12)',
            border: 'rgba(249, 115, 22, 0.3)',
            glow: 'rgba(249, 115, 22, 0.25)',
          },
          low: {
            DEFAULT: '#eab308',
            bg: 'rgba(234, 179, 8, 0.12)',
            border: 'rgba(234, 179, 8, 0.3)',
            glow: 'rgba(234, 179, 8, 0.25)',
          },
          info: {
            DEFAULT: '#38bdf8',
            bg: 'rgba(56, 189, 248, 0.12)',
            border: 'rgba(56, 189, 248, 0.3)',
            glow: 'rgba(56, 189, 248, 0.25)',
          },
        },
        cyber: {
          emerald: '#10b981',
          cyan: '#06b6d4',
          blue: '#3b82f6',
          purple: '#8b5cf6',
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Cascadia Code', 'Consolas', 'monospace'],
      },
      animation: {
        'scan': 'scan 2.5s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'pulse-subtle': 'pulseSubtle 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
      keyframes: {
        scan: {
          '0%, 100%': { top: '0%', opacity: '0.8' },
          '50%': { top: '95%', opacity: '0.4' },
        },
        pulseSubtle: {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.6' },
        },
      },
    },
  },
  plugins: [],
}
