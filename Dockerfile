FROM node:20-alpine AS builder

# better-sqlite3 heeft een build-toolchain nodig om zijn native module te
# compileren tijdens npm install — die toolchain (python3/make/g++) hoeft
# niet mee in de uiteindelijke image, vandaar deze aparte bouwfase.
RUN apk add --no-cache python3 make g++

WORKDIR /app
COPY server/package.json server/package-lock.json* ./server/
RUN cd server && npm install --omit=dev

# ---------- Uiteindelijke, kleinere image ----------
# Geen python3/make/g++ hierin — alleen wat er echt nodig is om de app
# te draaien. De al-gecompileerde node_modules (incl. het native
# better-sqlite3-binary) worden gewoon overgenomen uit de bouwfase.
FROM node:20-alpine

WORKDIR /app

COPY server/ ./server/
COPY src/ ./src/
COPY --from=builder /app/server/node_modules ./server/node_modules

# Hier schrijft de server zijn SQLite-database naartoe — koppel dit als
# volume in docker-compose.yml zodat accounts/gesprekken een herstart
# overleven.
ENV DATA_DIR=/app/data
ENV PORT=3000
EXPOSE 3000

# Draait bewust niet als root. Hergebruikt de "node"-gebruiker (uid/gid
# 1000) die al standaard in de officiële node-image zit — een NIEUWE
# gebruiker aanmaken op diezelfde uid/gid 1000 (zoals hier eerst stond)
# botst daarmee en breekt de build. LET OP: bij een bind mount (zoals
# ./relay-data:/app/data in docker-compose.yml) is de eigenaar op de HOST
# bepalend, niet wat hier in de image staat. Zorg dus dat de map op de
# host ook eigendom is van uid/gid 1000, bijvoorbeeld:
#   sudo chown -R 1000:1000 ./relay-data
# (zie de README voor de volledige uitleg). Zonder deze stap kan de
# container niet in die map schrijven en start de app niet correct op.
RUN mkdir -p /app/data && chown -R node:node /app/data
USER node

# Voor Docker's eigen HEALTHCHECK én voor `docker compose ps`/orchestrators
# die hierop letten. Gebruikt Node zelf i.p.v. curl/wget, om geen extra
# packages in de (bewust kleine) image te hoeven installeren.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/healthz', r => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"

CMD ["node", "server/index.js"]
