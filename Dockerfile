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

# Draait bewust niet als root. UID/GID 1000 is op de meeste Linux-
# distributies de standaard voor de eerste "echte" gebruiker — LET OP: bij
# een bind mount (zoals ./relay-data:/app/data in docker-compose.yml) is
# de eigenaar op de HOST bepalend, niet wat hier in de image staat. Zorg
# dus dat de map op de host ook eigendom is van uid/gid 1000, bijvoorbeeld:
#   sudo chown -R 1000:1000 ./relay-data
# (zie de README voor de volledige uitleg). Zonder deze stap kan de
# container niet in die map schrijven en start de app niet correct op.
RUN addgroup -g 1000 -S relay \
    && adduser -u 1000 -S relay -G relay \
    && mkdir -p /app/data \
    && chown -R relay:relay /app/data
USER relay

# Voor Docker's eigen HEALTHCHECK én voor `docker compose ps`/orchestrators
# die hierop letten. Gebruikt Node zelf i.p.v. curl/wget, om geen extra
# packages in de (bewust kleine) image te hoeven installeren.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/healthz', r => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"

CMD ["node", "server/index.js"]