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
    lib/                    Bootstrap en jQuery
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

### Berichten versleutelen met mod63 en HMAC-SHA-256

Wissel per bericht twee onafhankelijk gegenereerde, willekeurige sleutels persoonlijk uit. Plak ze in **Gedeelde mod63-sleutel** en **Gedeelde HMAC-sleutel**. Beide bevatten minstens 80 tekens uit het onderstaande alfabet en moeten verschillend zijn. De ontvanger gebruikt hetzelfde paar om lokaal te controleren en te ontsleutelen. Onderwerp en bericht worden samen versleuteld voordat de aanvraag vertrekt. Geen van beide sleutels komt in aanvragen, URL's, exports of browseropslag. Afzender, ontvanger, tijdstip en berichtlengte blijven zichtbaar voor de server.

Het alfabet is `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_` (indices 0–62). De browser zet `onderwerp + "\n" + bericht` om naar UTF-8. Elke byte wordt twee mod63-symbolen: `floor(byte / 63)` en `byte % 63`. Versleutelen telt bij elk symbool het overeenkomstige sleutelsymbool op, modulo 63; ontsleutelen trekt dit af. Er wordt nooit naar het begin van de sleutel teruggesprongen. Spaties, leestekens, hoofdletters en Unicode blijven behouden.

Een sleutel van 80 tekens biedt plaats aan 40 UTF-8-bytes inclusief het scheidingsteken: 39 bytes voor onderwerp en bericht samen. Het formulier toont hoeveel sleuteltekens nodig zijn. Genereer langere sleutels voor langere berichten, bijvoorbeeld:

```bash
python app/key-generator.py 10 --length 1600 --with-hmac --output keys.json
```

Met `--with-hmac` bevat `keys.json` een `keys`-array met objecten met `encryptionKey` en `hmacKey`. De standaardlengte van beide sleutels is 80; `--length` verlengt alleen de mod63-sleutel. Zonder `--with-hmac` blijft de oude uitvoer met losse mod63-sleutels behouden. De generator overschrijft geen bestaand bestand: bewaar het huidige bestand veilig voordat je een nieuw bestand genereert.

De browser berekent na versleuteling een HMAC-SHA-256 met de aparte HMAC-sleutel. De exacte invoer is de UTF-8-encoding van `JSON.stringify(["MOD63:2", ciphertext])`. De database bewaart `MOD63:2` als onderwerp en `MOD63:2:<ciphertext>:<hmac>` als body. De volledige HMAC bestaat uit 64 kleine hexadecimale tekens. De limiet van 2000 tekens omvat de volledige body: maximaal 1926 ciphertexttekens of 963 UTF-8-bytes inclusief de scheidende newline. De API accepteert voor nieuwe berichten uitsluitend dit formaat en weigert onbekende velden (zoals sleutelvelden). De server heeft de sleutels niet en kan alleen het formaat controleren, niet de HMAC.

Bij ontvangst controleert de browser eerst de HMAC met Web Crypto. Pas daarna wordt ontsleuteld en plaintext getoond. Gewijzigde ciphertext, een gewijzigde HMAC of een verkeerde HMAC-sleutel geven: **Integriteitscontrole mislukt: verkeerde sleutel of gewijzigd bericht.** Succesvol gecontroleerde en ontsleutelde berichten krijgen de melding **Integriteit gecontroleerd (HMAC-SHA-256).** Gebruik HTTPS of localhost voor Web Crypto.

Gebruik ieder sleutelpaar voor precies één bericht, ook als er nog sleuteltekens over zijn. Alleen SHA-256-vingerafdrukken van mod63-sleutels worden lokaal bewaard om opnieuw verzenden met dezelfde mod63-sleutel te blokkeren. Ontsleutelen blijft mogelijk; een mod63-sleutel waarmee je hebt ontsleuteld mag je niet gebruiken om zelf te verzenden. Na een netwerkfout wordt die sleutel als gebruikt beschouwd. Deze controle geldt alleen voor deze browser/origin en vervalt als de lokale opslag wordt gewist. Standaard gegenereerde `keys.json`-bestanden en backups worden uitgesloten van Git en de Docker-build; houd bestanden met andere namen ook buiten de repository en buildcontext.

Dit blijft een oefenimplementatie. De HMAC beschermt de versie en ciphertext, niet de afzender, ontvanger of het tijdstip. Iedereen met beide sleutels kan geldige berichten maken; opnieuw aanbieden van een geldig bericht wordt niet gedetecteerd. Een verkeerde mod63-sleutel kan ondanks een geldige HMAC onjuiste plaintext opleveren: de HMAC controleert de ciphertext met de HMAC-sleutel, niet de ingevoerde mod63-sleutel.

Bestaande plaintext- en `MOD63:1`-berichten blijven ongewijzigd in de database en exports. Oude mod63-berichten zijn met hun oorspronkelijke mod63-sleutel leesbaar, maar krijgen een waarschuwing dat hun integriteit niet gecontroleerd kan worden. Beschadigde versie-2-berichten worden geweigerd zonder terugval naar ongecontroleerde ontsleuteling. Wie zowel versie als inhoud wijzigt naar een oud formaat kan die oude leesroute bereiken; die toont altijd de waarschuwing en nooit een succesvolle integriteitscontrole. Zoeken filtert lokaal op afzender.

#### Manipulatie aantonen

1. Verstuur een testbericht met onderwerp `Test` en inhoud `Bedrag: 100` met een nieuw sleutelpaar. Open het als ontvanger en controleer dat het correct ontsleutelt.
2. Open op de server de database met `docker compose exec db psql -U unbreakable -d unbreakable` en zoek het testbericht in `"Messages"`.
3. Bewaar de originele body. Wijzig één teken in het ciphertextdeel, tussen `MOD63:2:` en de laatste dubbele punt, zonder de HMAC aan te passen. Bewaar het formaat en de lengte.
4. Vernieuw de berichtpagina en voer hetzelfde sleutelpaar in. De browser toont een integriteitsfout en geen plaintext. Herstel daarna de originele body.

De bestaande tests in `app/tests/crypto.test.mjs` beschrijven het oude, synchrone versie-1-formaat. Ze zijn niet aangepast voor versie 2.

Technologie: ASP.NET Core minimal API op .NET 10, Entity Framework Core met PostgreSQL 17, en vanilla JavaScript met Bootstrap, zonder build stap.

## Herkomst

Gebaseerd op [websec-vulnerable-dotnetcore](https://github.com/Splynter-Security/websec-vulnerable-dotnetcore), omgebouwd tot een berichtenapp met een SPA en een API, en bijgewerkt naar .NET 10.
