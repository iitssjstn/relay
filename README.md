# Relay

Eén chatgesprek, meerdere AI-modellen. Loopt de actieve AI tegen zijn
contextlimiet aan, dan neemt de volgende AI in de ketting het gesprek
automatisch over — inclusief de volledige geschiedenis.

Relay bestaat uit een simpele frontend (HTML/CSS/JS) en een kleine
Node.js-server met een SQLite-database. De server regelt accounts,
het bewaren van gesprekken/instellingen, én stuurt de AI-aanroepen
zelf door naar de provider die je instelt (Anthropic, OpenAI, Google,
etc.) — dat laatste is een bewuste server-side proxy, nodig omdat
sommige providers (zoals Groq) rechtstreekse browseraanroepen
blokkeren (CORS). De server bewaart of leest de inhoud van die
aanroepen niet, hij stuurt 'm alleen door. Je API-keys staan (net als
je gesprekken) in de database op je eigen server.

## Accounts en toegang

Alles regel je vanuit de app zelf, niks op de VPS:

1. Open de site. Er staan nog geen accounts, dus je krijgt meteen een
   registratieformulier zonder code-veld — het eerste account dat je
   aanmaakt wordt automatisch **beheerder**.
2. Log in met dat account. Rechtsonder in de zijbalk verschijnt een
   knop **"Beheer"**.
3. Klik daarop en stel een **registratiecode** in (minstens 6 tekens).
   Vanaf dat moment kan iedereen die die code kent zelf een account
   aanmaken — met eigen gebruikersnaam, wachtwoord, en eigen aparte
   gesprekken/AI-instellingen, niet zichtbaar voor andere accounts.
4. Deel de code met wie je toegang wilt geven (bijv. via een
   chat-app — niet publiceren).

Vanuit hetzelfde beheerscherm kun je:
- de registratiecode op elk moment wijzigen,
- registratie helemaal **sluiten** (geen nieuwe accounts meer, tot je
  een nieuwe code instelt),
- losse accounts **verwijderen** om iemands toegang in te trekken.

De registratiecode wordt nooit in platte tekst opgeslagen — alleen de
bcrypt-hash ervan, in de database.

## Automatisch bouwen via GitHub Actions

Dit repo bevat een workflow (`.github/workflows/docker-publish.yml`)
die bij elke push naar `main` automatisch een Docker image bouwt en
publiceert naar GitHub Container Registry (`ghcr.io`). Daardoor hoef
je op de VPS nooit lokaal te bouwen — je pullt gewoon het kant-en-klare
image.

**Eenmalig instellen, nadat je dit naar je eigen GitHub-repo hebt gepusht:**

1. Push naar `main` — de workflow draait automatisch (te volgen onder
   het tabblad *Actions* van je repo) en publiceert
   `ghcr.io/<jouw-gebruikersnaam>/<repo-naam>:latest`.
2. Ga naar je GitHub-profiel → *Packages* → het package dat net is
   aangemaakt → *Package settings* → zet zichtbaarheid op **Public**
   (anders moet de VPS ook inloggen bij ghcr.io om te kunnen pullen).
3. Pas in `docker-compose.yml` de regel `image:` aan naar
   `ghcr.io/<jouw-gebruikersnaam>/<repo-naam>:latest` (staat al goed
   als je gebruikersnaam/repo `iitssjstn/relay` is).

**Updaten op de VPS gaat vanaf dan zo:**

```bash
docker compose pull relay
docker compose up -d relay
```

Geen `git pull`, geen rebuild — je haalt gewoon de laatste gepubliceerde
image binnen. Accounts en gesprekken blijven staan, die leven in de
`relay-data`-map (zie hieronder), niet in het image.

## Starten (achter Nginx Proxy Manager)

**Stap 1 — `docker-compose.yml`.**

```yaml
services:
  relay:
    image: ghcr.io/iitssjstn/relay:latest
    container_name: relay
    restart: unless-stopped
    volumes:
      - ./relay-data:/app/data
```

De `volumes`-regel zorgt dat de database (accounts + gesprekken)
bewaard blijft bij een herstart of update. Verder is er niets in te
vullen — geen wachtwoorden, geen codes, dat regel je zo dadelijk in
de app zelf.

**Draait er al Nginx Proxy Manager op dezelfde VPS?** Zet dit
`relay`-blok dan direct in dezelfde `docker-compose.yml` als je NPM
en andere services — ze delen dan automatisch hetzelfde Docker-
netwerk, en je hoeft geen `ports:` toe te voegen. Draait Relay in een
losse `docker-compose.yml`, dan heb je een gedeeld extern netwerk
nodig; zoek de naam op met `docker network ls` en voeg toe:

```yaml
    networks:
      - npm_network
networks:
  npm_network:
    external: true
    name: npm_network   # <-- de echte naam van jouw NPM-netwerk
```

**Stap 2 — maak de data-map aan en zet 'm klaar voor de container.**

De container draait bewust niet als root. Daarom moet de map die je
zo dadelijk koppelt, al bestaan én eigendom zijn van uid/gid 1000
(de gebruiker waarmee de container draait) — anders kan Relay niet
in zijn eigen database schrijven en start de app niet op:

```bash
mkdir -p ./relay-data
sudo chown -R 1000:1000 ./relay-data
```

**Stap 3 — start de container.**

```bash
docker compose up -d
```

**Stap 4 — voeg een Proxy Host toe in NPM.**

In de NPM-webinterface: *Proxy Hosts → Add Proxy Host*
- Domain Names: bijv. `relay.jouwdomein.nl`
- Scheme: `http`
- Forward Hostname / IP: `relay` (de container-naam)
- Forward Port: `3000`
- SSL-tab: vraag een Let's Encrypt-certificaat aan en zet "Force SSL" aan
  — belangrijk, want er gaan wachtwoorden en API-keys doorheen

Daarna is de app bereikbaar op `https://relay.jouwdomein.nl`.

**Stap 5 — open de site en maak je (beheerders-)account aan.**

Zie "Accounts en toegang" hierboven.

Stoppen:

```bash
docker compose down
```

**Werkt de container niet, of blijft hij steeds herstarten?** Controleer
eerst de status en gezondheid:

```bash
docker compose ps        # 'healthy' zodra /healthz goed antwoordt
docker compose logs relay
```

Zie je een schrijffout naar `/app/data` in de logs, dan is stap 2
hierboven (de `chown`) waarschijnlijk overgeslagen.

## Gebruik

1. Log in.
2. Klik links op **"+ AI toevoegen aan de ketting"** en vul per AI een
   provider (Anthropic, OpenAI, Google Gemini, of een aangepast
   OpenAI-compatibel endpoint), model en API-key in.
3. Voeg zo meerdere AI's toe en zet ze in de gewenste volgorde met de
   ↑/↓-knoppen.
4. Begin het gesprek. Bereikt de actieve AI zijn contextlimiet, dan
   schakelt Relay automatisch door naar de volgende in de ketting.
5. Gesprekken en je AI-configuratie worden automatisch bewaard bij je
   account, zodat je op elk apparaat gewoon kan inloggen en verdergaan.

## Data en privacy

- Accounts, gesprekken en AI-instellingen (incl. API-keys) staan in
  een SQLite-database op je eigen server, gekoppeld aan het account
  waarmee je bent ingelogd — niet zichtbaar voor andere accounts.
- AI-aanroepen lopen via de Relay-server naar de provider die je hebt
  ingesteld (server-side proxy, nodig omdat sommige providers directe
  browseraanroepen blokkeren). De server logt of bewaart de inhoud
  daarvan niet — hij stuurt 'm alleen gestreamd door.
- Wachtwoorden én de registratiecode worden gehasht opgeslagen
  (bcrypt), nooit in platte tekst.
- Inloggen/registreren is beperkt (rate limiting) tegen herhaald
  geautomatiseerd gokken; beveiligingsheaders (CSP, HSTS e.a.) staan
  standaard aan.
- Beheerdersacties (registratiecode wijzigen, gebruiker verwijderen)
  worden gelogd — te bekijken via Accountmenu → Beheer → "Toon
  logboek".
- Zorg dat de Proxy Host in NPM SSL afdwingt ("Force SSL"), zodat
  wachtwoorden en API-keys niet onversleuteld over het netwerk gaan.
- Gebruik alleen API-keys waar je zelf recht toe hebt, en geef de
  registratiecode alleen aan mensen die je vertrouwt.
- Gebruik de knoppen "Exporteer config" / "Importeer config" om je
  AI-instellingen als back-up te bewaren.

## Auteursrecht

Elke AI-provider heeft eigen gebruiksvoorwaarden. Respecteer de
herpublicatie- en auteursrechtregels van de provider die je gebruikt
— output overnemen als eigen werk of zonder toestemming commercieel
herpubliceren kan daarmee in strijd zijn.

## Projectstructuur

```
.
├── .github/
│   ├── dependabot.yml       # houdt npm/Actions/baseimage automatisch actueel
│   └── workflows/
│       └── docker-publish.yml  # bouwt & publiceert image naar ghcr.io
├── .dockerignore
├── .env.example         # optionele technische configuratie (nooit admin-credentials)
├── Dockerfile            # multi-stage node:20-alpine, draait als niet-root
├── docker-compose.yml    # één service, pullt image van ghcr.io
├── server/
│   ├── index.js           # Express-API: auth, admin, gesprekken, instellingen
│   ├── db.js                # SQLite-schema
│   ├── secrets.js           # optionele Docker-Secret/env-var helper (JWT_SECRET)
│   └── package.json
├── src/
│   └── index.html            # de volledige frontend (HTML/CSS/JS)
└── README.md

Op je VPS komt daarnaast (niet in git):
└── relay-data/   # SQLite-database (accounts, gesprekken, registratiecode-hash)
```
