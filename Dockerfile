FROM node:20-alpine

# better-sqlite3 heeft een build-toolchain nodig om zijn native module
# te compileren tijdens npm install.
RUN apk add --no-cache python3 make g++

WORKDIR /app

COPY server/package.json server/package-lock.json* ./server/
RUN cd server && npm install --omit=dev

COPY server/ ./server/
COPY src/ ./src/

# Hier schrijft de server zijn SQLite-database naartoe — koppel dit als
# volume in docker-compose.yml zodat accounts/gesprekken een herstart
# overleven.
ENV DATA_DIR=/app/data
ENV PORT=3000
EXPOSE 3000

CMD ["node", "server/index.js"]
