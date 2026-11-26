FROM node:22-slim

WORKDIR /app

COPY package.json package-lock.json* tsconfig.json next.config.ts postcss.config.mjs ./
RUN npm ci || npm install

COPY app ./app
COPY components ./components
COPY lib ./lib
COPY ts ./ts
COPY atlas.ts metadata.json ./

RUN npm run build

ENV NODE_ENV=production
ENV PORT=3000
ENV ATLAS_DATA_DIR=/app/data

RUN mkdir -p /app/data && chmod 700 /app/data

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/api/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["npm", "run", "start"]
