import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  // GitHub Pages serves a project site from `/<repo>/`, not from the root, so
  // every asset URL has to carry that prefix or the published page loads a
  // blank screen with four 404s. Set `VITE_BASE=/sentry/` in the Pages
  // workflow; local builds and the dev server keep the root.
  //
  // `lib/snapshot.ts` reads the recording through `import.meta.env.BASE_URL`,
  // so it follows this automatically.
  base: process.env.VITE_BASE ?? "/",
  plugins: [react()],
  server: { port: 5173 },
  test: { environment: "jsdom", globals: true },
});
