FROM node:22-slim

WORKDIR /app

COPY lib/biotp-ts /app/lib/biotp-ts
COPY server-ts /app/server-ts

WORKDIR /app/lib/biotp-ts
RUN npm install && npm run build

WORKDIR /app/server-ts
RUN npm install && npm run build

CMD ["node", "dist/server.js"]
