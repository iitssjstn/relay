const fs = require('fs');
const path = require('path');

// Docker Secrets worden als bestand gemount op /run/secrets/<naam> — dat
// bestand staat NIET in `docker inspect`, `ps aux` of `/proc/*/environ`,
// in tegenstelling tot env_file/environment-variabelen. Dit verkleint het
// aanvalsoppervlak, het is geen garantie: wie root op de host heeft, kan
// nog steeds elk bestand lezen dat de container zelf ook kan lezen.
//
// SECRETS_DIR is aanpasbaar zodat dit ook lokaal (buiten Docker) te
// testen is; in productie laat je deze gewoon op de Docker-standaard staan.
const SECRETS_DIR = process.env.SECRETS_DIR || '/run/secrets';

function getSecret(secretName, envVarFallback){
  const secretPath = path.join(SECRETS_DIR, secretName);
  try {
    return fs.readFileSync(secretPath, 'utf-8').trim();
  } catch {
    // Geen secrets-bestand gevonden — terugvallen op een env-variabele,
    // als die is opgegeven (handig voor lokaal draaien zonder Docker).
    return envVarFallback ? (process.env[envVarFallback] || null) : null;
  }
}

module.exports = { getSecret };
