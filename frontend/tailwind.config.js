/** @type {import('tailwindcss').Config} */

export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: { 
      keyframes: {
        'jello-vertical': {
          '0%': { transform: 'scale3d(1, 1, 1)' },
          '30%': { transform: 'scale3d(0.75, 1.25, 1)' },
          '40%': { transform: 'scale3d(1.25, 0.75, 1)' },
          '50%': { transform: 'scale3d(0.85, 1.15, 1)' },
          '65%': { transform: 'scale3d(1.05, 0.95, 1)' },
          '75%': { transform: 'scale3d(0.95, 1.05, 1)' },
          '100%': { transform: 'scale3d(1, 1, 1)' },
        },
      },
      fontFamily: {
        abril: ['"Abril Fatface"', 'cursive'],
        vibes: ['"Great Vibes"', 'cursive'],
      },
      animation: {
        'jello-vertical': 'jello-vertical 0.9s both',
      },
      variants: {
        extend: {
          animation: ['group-hover'],
        }
      },
      
      backgroundImage: {
        'search-icon': "url('/assets/header/search-icn.png')",
        'customs-gradients': 'linear-gradient(to bottom, rgba(255, 255, 255, 0) 20px, rgba(255, 255, 255, 0.9) 10px)',
      }, colors: {
      customBlue: '#001C54', // Adds custom color named "customBlue"
    },},
  },
  plugins: [ function({ addUtilities }) {
    const newUtilities = {
      '.scrollbar-hide': {
        '-ms-overflow-style': 'none',
        'scrollbar-width': 'none',
        '&::-webkit-scrollbar': {
          display: 'none',
        },
      },
    }
    addUtilities(newUtilities);
  }],
}