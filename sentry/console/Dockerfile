# SENTRY operator console.
#
# Two stages: node builds the bundle, nginx serves it. The runtime image carries
# no node and no source, because a console container that can execute the
# toolchain that built it is a larger attack surface than one that can only
# serve static files.
FROM node:22-alpine AS build

WORKDIR /app

COPY package.json package-lock.json ./
# `npm ci` rather than `npm install`: the lockfile is the pinned set, and a
# build that silently resolves a newer transitive dependency is not the build
# that was tested.
RUN npm ci

# postcss.config.js and tailwind.config.js are load-bearing and were missing
# here. Without them Vite still builds and still emits a stylesheet — one that
# contains the literal `@tailwind base;` directives, unprocessed. The bundle is
# valid, the page renders, every utility class is inert, and nothing in the
# build reports a problem.
COPY tsconfig.json vite.config.ts index.html postcss.config.js tailwind.config.js ./
COPY scripts/ ./scripts/
COPY src/ ./src/

# Baked at build time, because Vite substitutes VITE_* at compile time — there
# is no runtime environment for a static bundle. A deployment pointing at a
# different control plane is a different build, and says so.
ARG VITE_API_BASE=http://localhost:8080
ENV VITE_API_BASE=$VITE_API_BASE

# The prose linter runs in the build, not just in CI. design/91-CONSOLE.md
# prohibits copy that defines a term for the reader; enforcing it here means an
# image cannot be produced with teaching prose in it.
RUN node scripts/lint-prose.mjs && npm run build

FROM nginx:1.27-alpine

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

# Dialled by address rather than by name. nginx now listens on both stacks, so
# `localhost` would work either way — but a healthcheck that depends on which
# family the resolver returns first is one hosts-file change away from declaring
# a working service dead, and this check is the one thing that must not have a
# second failure mode of its own.
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
    CMD wget -qO- http://127.0.0.1/ >/dev/null || exit 1
