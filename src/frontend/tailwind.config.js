const { fontFamily } = require("tailwindcss/defaultTheme");

/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: "class",
  content: [
    "./index.html",
    "./src/**/*.{ts,tsx,js,jsx}"
  ],
  theme: {
    extend: {
      fontFamily: {
        mono: ["Fira Code", ...fontFamily.mono],
      },
      colors: {
        terminal: "#00ff00",
      },
    },
  },
  plugins: [],
};
