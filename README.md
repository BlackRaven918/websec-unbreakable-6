# Unbreakable

Starter app voor het vak Cyber Security Advanced aan AP Hogeschool.

Unbreakable is een kleine berichtenapp. Je kiest een naam, je stuurt berichten naar anderen en je leest je inbox. De app werkt, maar is nog helemaal niet veilig. Doorheen het semester maken jullie ze beter: een pipeline en een WAF, cryptografie, inloggen, autorisatie en geheimenbeheer.

> **Let op:** deze app bevat bewust zwakke plekken. Gebruik ze enkel in je eigen labomgeving en nooit met echte gegevens.

## Starten

Je hebt enkel Docker nodig, met de compose plugin.

```bash
git clone <jouw repo>
cd <jouw repo>
docker compose up -d --build
```

Surf daarna naar `http://localhost:8080`, of naar poort 8080 van je server. Vul een naam in, bijvoorbeeld **Anna**, **Bram** of **Chris**. Een nieuwe databank bevat geen voorbeeldberichten.

Stoppen doe je met `docker compose down`. Wil je opnieuw beginnen met een lege databank, gebruik dan `docker compose down -v`.

Leeft de app? `curl http://localhost:8080/health` geeft `ok`.

## Opbouw

De app bestaat uit twee delen in één container: een single page app (SPA) die in je browser draait, en een API op de server. De SPA praat met de API in JSON. Open de developer tools van je browser (tabblad Network) om te zien wat er over en weer gaat.

```
docker-compose.yml          de app en een PostgreSQL databank
app/
  Program.cs                de API, en opstarten van de databank
  Models/Message.cs         een bericht
  Data/                     databanktoegang (Entity Framework Core)
  wwwroot/                  de SPA
    index.html
    js/app.js               de schermen
    js/api.js               alle calls naar de API
    js/crypto.js            versleutelen en HMAC in de browser (mod 37)
    lib/                    Bootstrap en jQuery
  tests/crypto.test.mjs     tests voor de versleuteling (node --test)
docs/threat-model.md        basis threat model van de starter app
```

### De API

| Methode | Pad | Doet |
|---|---|---|
| GET | `/health` | leeft de app? |
| GET | `/api/users` | alle gekende namen |
| GET | `/api/messages` | je inbox, optioneel `?from=<naam>` |
| GET | `/api/messages/{id}` | één bericht |
| POST | `/api/messages` | bericht versturen |
| DELETE | `/api/messages/{id}` | bericht verwijderen |
| GET | `/api/messages/export` | je inbox als JSON |

Wie je bent, stuurt de SPA mee in de header `X-User`.

### Berichten versleutelen met mod 37 en HMAC-SHA-256

De browser versleutelt elk bericht met een one-time pad in modulo 37. De server krijgt alleen de versleutelde tekst, nooit het bericht en nooit een sleutel.

**Het codeboek.** Verzender en ontvanger wisselen vooraf persoonlijk een codeboek en een HMAC-sleutel uit, bijvoorbeeld op een USB-stick of op papier. Niet via de app, de repo of een chat. Maak ze op je eigen pc, niet op de server:

```bash
tr -dc 'A-Z0-9_' < /dev/urandom | fold -w 40 | head -n 50 | nl > codeboek.txt
tr -dc 'A-Za-z0-9_' < /dev/urandom | head -c 40 > hmac-sleutel.txt
```

Elke lijn uit het codeboek is een sleutel van 40 tekens die je maar één keer gebruikt. Spreek af wie de even en wie de oneven lijnen neemt. De HMAC-sleutel (minstens 32 tekens) mag je wel hergebruiken. Zet `codeboek.txt` en `hmac-sleutel.txt` nooit in de repo. `app/key-generator.py` hoort bij de vroegere mod63-versie; voor mod 37 gebruik je het codeboek hierboven.

**Alleen hoofdletters.** Het alfabet heeft 37 tekens: `A`–`Z` = 0–25, `0`–`9` = 26–35 en `_` = 36. Kleine letters worden hoofdletters en een spatie wordt `_`. Andere tekens, zoals `é`, `!` of `?`, weigert de app met een foutmelding. Het verschil tussen hoofdletters en kleine letters gaat dus verloren: de ontvanger leest alles in hoofdletters. Een bericht is maximaal 40 tekens, zo lang als een lijn. Er is geen onderwerp meer, want dat zou leesbaar in de databank staan.

**Versturen.** Vul de ontvanger en het bericht in, plak een volledige lijn uit het codeboek (het nummer en de 40 tekens, zoals `nl` ze toont) en de HMAC-sleutel.

- De browser rekent per teken C = (P + K) mod 37. Het voorbeeld uit de les: `HELLO` met de sleutel `AI8OP` geeft `HMIZ3`.
- Daarna berekent de browser met Web Crypto een HMAC-SHA-256 over `JSON.stringify(["MOD37:1", afzender, ontvanger, lijnnummer, ciphertext])`.
- Naar de API gaan alleen het onderwerp `MOD37:1` en de body `MOD37:1:<lijnnummer>:<ciphertext>:<hmac>`. De API controleert alleen dat formaat; ze heeft geen sleutels.

**Lezen.** Het bericht toont welke lijn uit het codeboek het gebruikt. De ontvanger plakt die lijn en de HMAC-sleutel. De browser controleert eerst de HMAC met `verify` en rekent pas daarna terug met P = (C − K) mod 37. Klopt de HMAC niet, dan toont de app **Integriteitscontrole mislukt: verkeerde HMAC-sleutel of gewijzigd bericht.** en geen tekst. Web Crypto werkt alleen via HTTPS of localhost.

De browser bewaart een SHA-256-vingerafdruk van elke gebruikte lijn in `localStorage` en weigert om dezelfde lijn een tweede keer te versturen. Dat werkt alleen in dezelfde browser, dus de echte bescherming blijft de afspraak dat je elke lijn maar één keer gebruikt. Oude, onversleutelde berichten toont de app met een waarschuwing.

**Wat niet beschermd is.** Afzender, ontvanger, tijdstip, lengte en lijnnummer blijven zichtbaar voor de server. Een oud bericht dat opnieuw wordt ingevoegd (replay), wordt niet opgemerkt, en iedereen kan berichten verwijderen. De HMAC-sleutel is gedeeld, dus hij bewijst niet wie van de twee een bericht maakte.

#### Manipulatie aantonen

1. Verstuur een testbericht met een nieuwe lijn uit het codeboek en open het als ontvanger. Het bericht wordt correct ontsleuteld.
2. Zoek op de server de naam van de databankcontainer met `docker ps` en open de databank met `docker exec -it <naam van de db-container> psql -U unbreakable -d unbreakable`.
3. Wijzig één teken in het ciphertextdeel van de body, tussen het lijnnummer en de laatste dubbele punt, zonder de HMAC aan te passen.
4. Vernieuw de berichtpagina en ontsleutel opnieuw met dezelfde lijn en HMAC-sleutel. De app toont de integriteitsfout en geen tekst.

De tests in `app/tests/crypto.test.mjs` controleren mod 37 (ook `HELLO` + `AI8OP` = `HMIZ3`), de HMAC en dat er alleen ciphertext naar de API gaat. Je start ze met `node --test app/tests/crypto.test.mjs`.

Technologie: ASP.NET Core minimal API op .NET 10, Entity Framework Core met PostgreSQL 17, en vanilla JavaScript met Bootstrap, zonder build stap.

## Herkomst

Gebaseerd op [websec-vulnerable-dotnetcore](https://github.com/Splynter-Security/websec-vulnerable-dotnetcore), omgebouwd tot een berichtenapp met een SPA en een API, en bijgewerkt naar .NET 10.
