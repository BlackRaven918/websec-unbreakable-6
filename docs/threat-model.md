# Basis threat model van de starter app

Dit is het vertrekpunt voor wie opdracht 1 niet heeft. Het beschrijft de starter app zoals ze is: zonder pipeline, zonder WAF, zonder inloggen. Vul het aan in elke opdracht.

## Architectuur

```mermaid
flowchart LR
  subgraph Internet
    U([Gebruiker<br/>browser met de SPA])
    D([Developer<br/>laptop])
    GH[(GitHub<br/>repository)]
  end
  subgraph Server["Server (Linux, Docker)"]
    subgraph Docker["Docker netwerk"]
      A((App<br/>statische SPA en API))
      DB[(PostgreSQL)]
    end
  end
  U -- "1. HTTP, poort 8080<br/>SPA laden, geen authenticatie" --> A
  U -- "2. HTTP, poort 8080, JSON naar /api<br/>naam in de header X-User" --> A
  A -- "3. SQL over TCP, poort 5432<br/>wachtwoord" --> DB
  D -- "4. SSH, poort 22<br/>rootwachtwoord" --> Server
  D -- "5. HTTPS<br/>GitHub account" --> GH
  Server -- "6. HTTPS<br/>publieke repo, geen authenticatie" --> GH
```

Vertrouwensgrenzen: tussen de browser en de server, tussen het internet en de server, en tussen de server en het Docker netwerk. De API moet toegangscontrole en invoerformaat zelf controleren: een aanvaller kan zijn eigen client aanpassen. Voor de end-to-end bescherming controleert de browser van de ontvanger bovendien de HMAC met een geheime sleutel die de server niet krijgt.

## Mod63 met HMAC-SHA-256

Nieuwe berichten gebruiken twee onafhankelijk gegenereerde, persoonlijk gedeelde sleutels: een mod63-sleutel en een aparte HMAC-sleutel. De browser versleutelt onderwerp en inhoud, en authenticeert daarna de UTF-8-encoding van `JSON.stringify(["MOD63:2", ciphertext])` met HMAC-SHA-256. De body bevat `MOD63:2:<ciphertext>:<hmac>`; de API controleert uitsluitend het formaat. De browser van de ontvanger verifieert de HMAC voordat hij ontsleutelt. Bij een fout wordt geen plaintext getoond. Sleutels worden niet verzonden of opgeslagen; alleen een vingerafdruk van de mod63-sleutel blijft lokaal voor de bestaande hergebruikcontrole.

Dit detecteert wijzigingen in ciphertext of HMAC door iemand zonder HMAC-sleutel. Afzender, ontvanger en tijdstip zijn niet meebeschermd. Het voorkomt geen replay, verwijderen van berichten of vervalsing door iemand met beide sleutels. Een geldige HMAC bevestigt niet dat de ingevoerde mod63-sleutel juist is. Oude plaintext- en versie-1-berichten blijven leesbaar met een waarschuwing en krijgen geen integriteitsgarantie; een downgrade naar het oude formaat is daarom niet cryptografisch uitgesloten. De bestaande mod63-oefenversleuteling wordt niet vervangen door een standaard encryptie-algoritme.

Deze bescherming veronderstelt vertrouwde browsercode: een gecompromitteerde server die kwaadaardige JavaScript serveert, kan sleutels onderscheppen of controles uitschakelen. HTTPS blijft nodig voor veilig laden en Web Crypto.

## Dreigingen

Formulering: een A doet B op C door D, wat leidt tot E.

| # | STRIDE | Dreiging | Maatregel | Opdracht |
|---|---|---|---|---|
| 1 | Spoofing | Een gebruiker zet de naam van iemand anders in de header X-User, door het ontbreken van authenticatie, wat leidt tot het lezen van andermans berichten | Inloggen via een identity provider, tokens die de API valideert | 4 |
| 2 | Information disclosure | Een aanvaller luistert het verkeer af op flow 1 en 2, door het gebruik van HTTP, wat leidt tot het lekken van berichten | HTTPS | 2 |
| 3 | Information disclosure | Een beheerder of aanvaller met toegang tot de databank leest alle berichten, doordat ze onversleuteld bewaard worden, wat leidt tot verlies van vertrouwelijkheid | End to end encryptie | 3 |
| 4 | Elevation of privilege | Een gebruiker vraagt een bericht op met het id van iemand anders, door het ontbreken van autorisatie, wat leidt tot het lezen of verwijderen van andermans berichten | Autorisatie per bericht | 5 |
| 5 | Information disclosure | Iemand met toegang tot de repository leest het databankwachtwoord, doordat het in de configuratie staat, wat leidt tot volledige toegang tot de databank | Geheimen in een secrets manager | 6 |
| 6 | Tampering | Een aanvaller stuurt kwaadaardige invoer via een invoerveld, door onvoldoende validatie of encoding, wat leidt tot het uitvoeren van code of queries | Secure coding, SAST en een WAF | 2 |
| 7 | Tampering | Een aanvaller verstopt kwaadaardige code in een bibliotheek die de app gebruikt, door het ontbreken van controle op afhankelijkheden, wat leidt tot overname van de app | SCA in de pipeline | 2 |
| 8 | Spoofing | Een aanvaller raadt het rootwachtwoord van de server via flow 4, door aanmelden met wachtwoord, wat leidt tot overname van de server | SSH sleutels, fail2ban | 2 |
| 9 | Denial of service | Een aanvaller overspoelt de app met requests, door het ontbreken van rate limiting, wat leidt tot onbeschikbaarheid | Rate limiting in de WAF | 2 |
| 10 | Repudiation | Een gebruiker ontkent dat hij een bericht stuurde, doordat de afzender niet bewezen wordt en er geen logging is, wat leidt tot discussie zonder bewijs | Authenticatie, handtekeningen en logging | 3 en 4 |
| 11 | Tampering | Een aanvaller met schrijftoegang tot de databank wijzigt ciphertext, waardoor de ontvanger gewijzigde inhoud kan lezen | HMAC-SHA-256 met aparte sleutel; controle in de browser vóór ontsleuteling voor versie 2 | 3 |
