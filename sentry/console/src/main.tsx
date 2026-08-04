import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { App } from "./App";
import "./index.css";

const client = new QueryClient({
  defaultOptions: {
    queries: {
      // A failed request must surface as a failure, not be retried into
      // looking like a slow one. The Table renders the error; retrying three
      // times first only delays the operator learning the control plane is
      // down.
      retry: false,
      refetchOnWindowFocus: false,
      staleTime: 5_000,
    },
  },
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={client}>
      <App />
    </QueryClientProvider>
  </StrictMode>,
);
