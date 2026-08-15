# Relay

Eén chatgesprek, meerdere AI-modellen. Loopt de actieve AI tegen zijn
contextlimiet aan, dan neemt de volgende AI in de ketting het gesprek
automatisch over — inclusief de volledige geschiedenis.

Relay is een volledig statische, client-side webapp (HTML/CSS/JS, geen
build-stap, geen backend, geen database). Docker draait hier alleen
nginx om het bestand te serveren; alle AI-aanroepen gebeuren
rechtstreeks vanuit je eigen browser naar de providers die je zelf
instelt.

## Starten

```bash
git clone <jouw-repo-url> relay
cd relay
docker compose up -d
```

Open daarna [http://localhost:8080](http://localhost:8080).

Stoppen:

```bash
docker compose down
```

Poort aanpassen? Wijzig in `docker-compose.yml` de regel
`"8080:80"` naar bijvoorbeeld `"3000:80"`.

## Gebruik

1. Klik links op **"+ AI toevoegen aan de ketting"** en vul per AI een
   provider (Anthropic, OpenAI, Google Gemini, of een aangepast
   OpenAI-compatibel endpoint), model en API-key in.
2. Voeg zo meerdere AI's toe en zet ze in de gewenste volgorde met de
   ↑/↓-knoppen.
3. Begin het gesprek. Bereikt de actieve AI zijn contextlimiet, dan
   schakelt Relay automatisch door naar de volgende in de ketting.
4. Gesprekken en je AI-configuratie worden automatisch lokaal
   bewaard, zodat je de volgende dag verder kunt.

## Data en privacy

- Alles (API-keys, gesprekken, instellingen) wordt opgeslagen in de
  **localStorage van je eigen browser**, per apparaat/browser — niet
  op de server of in de Docker-container.
- Er wordt niets naar een server van derden gestuurd; API-calls gaan
  rechtstreeks van jouw browser naar de provider die je hebt
  ingesteld.
- Gebruik dit dus bij voorkeur niet op een gedeelde of publieke
  computer, en gebruik alleen API-keys waar je zelf recht toe hebt.
- Gebruik de knoppen "Exporteer config" / "Importeer config" om je
  instellingen (incl. keys) mee te nemen naar een andere browser of
  machine, of als back-up.

## Auteursrecht

Elke AI-provider heeft eigen gebruiksvoorwaarden. Respecteer de
herpublicatie- en auteursrechtregels van de provider die je gebruikt
— output overnemen als eigen werk of zonder toestemming commercieel
herpubliceren kan daarmee in strijd zijn.

## Projectstructuur

```
.
├── Dockerfile          # nginx:alpine, serveert src/
├── docker-compose.yml  # één service, poort 8080
├── src/
│   └── index.html       # de volledige app (HTML/CSS/JS)
└── README.md
```
