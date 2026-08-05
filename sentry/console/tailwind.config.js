/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      // Mapped onto the CSS variables in index.css rather than restated, so a
      // component reaching for var(--crit) and one reaching for text-crit
      // cannot drift to different colours.
      //
      // `<alpha-value>` is what makes an opacity modifier work. Without it
      // Tailwind compiles `bg-line/40` to `rgb(#1e232b / 0.4)`, decides that is
      // not a colour, and emits nothing — the utility exists in the markup and
      // nowhere in the stylesheet.
      colors: {
        bg: "rgb(var(--bg) / <alpha-value>)",
        panel: "rgb(var(--panel) / <alpha-value>)",
        line: "rgb(var(--line) / <alpha-value>)",
        tx1: "rgb(var(--tx1) / <alpha-value>)",
        tx2: "rgb(var(--tx2) / <alpha-value>)",
        tx3: "rgb(var(--tx3) / <alpha-value>)",
        tx4: "rgb(var(--tx4) / <alpha-value>)",
        ok: "rgb(var(--ok) / <alpha-value>)",
        warn: "rgb(var(--warn) / <alpha-value>)",
        crit: "rgb(var(--crit) / <alpha-value>)",
        info: "rgb(var(--info) / <alpha-value>)",
      },
      fontFamily: {
        sans: ["Avenir Next", "Segoe UI", "Helvetica Neue", "sans-serif"],
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
    },
  },
  plugins: [],
};
