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
        navy:    '#0f172a', /* slate-900 */
        slate: {
          dark:  '#1e293b', /* slate-800 */
          mid:   '#334155', /* slate-700 */
        },
        cyan: {
          DEFAULT: '#22d3ee', /* cyan-400 */
          dim: '#0891b2',     /* cyan-600 */
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      animation: {
        'spin-slow':  'spin 3s linear infinite',
        'pulse-slow': 'pulse 3s ease-in-out infinite',
      },
      backdropBlur: {
        xs: '2px',
      },
    },
  },
  plugins: [],
}
