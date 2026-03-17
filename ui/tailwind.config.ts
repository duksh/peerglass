import type { Config } from 'tailwindcss'

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        terminal: {
          bg:       '#0d1117',
          surface:  '#161b22',
          border:   '#30363d',
          green:    '#39d353',
          cyan:     '#58b3c2',
          yellow:   '#e3b341',
          red:      '#f85149',
          muted:    '#8b949e',
          text:     '#c9d1d9',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Cascadia Code', 'monospace'],
      },
    },
  },
  plugins: [],
} satisfies Config
