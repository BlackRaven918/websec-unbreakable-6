# Pipeline en aanvaarde bevindingen

Groep g06, Jasper Vanhoutte en Mohammed Ben Hammou.

## Scans en DSOMM

De workflow `Scan en deploy` (`.github/workflows/main.yml`) draait bij elke push. De deploy start alleen op main en alleen als de drie scans groen zijn.

| Scan | Tool | DSOMM-activiteit | Wanneer faalt de pipeline? |
|---|---|---|---|
| Secret scanning | gitleaks | Test for stored secrets in code (Test and Verification, Static depth for infrastructure, niveau 1) | Bij elk nieuw geheim dat niet in `.gitleaksignore` staat |
| SAST | CodeQL (C# en JavaScript) | Static analysis for important server side components en Static analysis for important client side components (Static depth for applications, niveau 3) | Bij een open melding met ernst high of critical |
| SCA | OSV-Scanner | Software Composition Analysis (server side) (Static depth for applications, niveau 2) | Bij een nieuwe kwetsbaarheid die niet in `osv-scanner.toml` staat |
| Uitrollen | Self-hosted runner en Docker Compose | Automated deployment process (Build and Deployment, Deployment, niveau 1) | Als de HTTPS-healthcheck via BunkerWeb niet lukt |

Link met opdracht 1: daar kozen we niveau 3 voor Static depth for applications (SAST op client en server, SCA aan client- en serverzijde) en voor Static depth for infrastructure (secret scanning). CodeQL dekt nu SAST op client en server, OSV-Scanner de SCA aan de serverkant en gitleaks het secret scanning in code. Nog niet gehaald uit opdracht 1: SCA aan de clientkant (jQuery en Bootstrap in `wwwroot/lib`), SBOM, image scanning en het signeren van images (Build, niveau 3).

Andere DSOMM-activiteiten die we invullen: Simple false positive treatment en Treatment of defects with high or critical severity (Consolidation, niveau 1), Environment depending configuration parameters (secrets) (Deployment, niveau 2) en Pinning of artifacts (Build, niveau 2) voor de actions die op een commit staan.

## Wat is voor ons kritiek?

- **CodeQL:** een melding met security severity high of critical (vanaf 7.0). Alleen critical was te weinig: de SQL-injectie in de zoekfunctie is "maar" high (8.8) en zou dan nooit de pipeline laten falen.
- **gitleaks:** elk nieuw geheim, want een gelekt geheim is meteen bruikbaar.
- **OSV-Scanner:** elke nieuwe kwetsbaarheid in een package.

Let op: een melding in het tabblad Security laat de pipeline op zich niet falen. Daarom haalt de laatste stap van `codeql.yml` de open meldingen op via de API en stopt de pipeline als er een high of critical bij zit.

## Aanvaarde bevindingen van de eerste run

Wat de eerste run op de ongewijzigde app vond, hebben we aanvaard. Per bevinding: is het een echt probleem of een false positive, en waarom kan het nu?

| Tool | Bevinding | Plek | Echt of false positive | Waarom kan het nu? | Waar aanvaard |
|---|---|---|---|---|---|
| CodeQL | SQL-injectie (`cs/sql-injection`, high) | `app/Program.cs:89` | Echt: `q` en `X-User` gaan rechtstreeks in `FromSqlRaw` | Bewust lek van de oefenapp, er staan geen echte gegevens in. De WAF houdt de gewone vorm tegen, maar via X-User niet, dus dit moet later in de code opgelost worden | Security, melding #7 |
| CodeQL | DOM XSS (`js/xss`, high) | `app/wwwroot/js/app.js:101` | Echt: de zoekterm gaat via jQuery `.html()` in de pagina | Bewust lek, geen echte gebruikers. De WAF blokkeert gewone script-payloads. Later oplossen met `.text()` of `escapeHtml` | Security, melding #1 |
| CodeQL | `js/unsafe-html-expansion` (medium) | `app/wwwroot/lib/jquery/dist/jquery.js:5796` | Echt: jQuery 3.3.1 heeft CVE-2020-11022 en de app gebruikt `.html()` | Oefenapp zonder echte gebruikers. jQuery moet naar 3.5.0 of hoger. OSV ziet dit niet omdat `wwwroot/lib` geen manifest heeft | Security, melding #6 |
| CodeQL | `js/xss-through-dom` (high), 4 keer | `app/wwwroot/lib/bootstrap/dist/js/bootstrap.js` en `bootstrap.bundle.js` | False positive voor deze app | Bootstrap 4.1.3 JS wordt niet geladen, `index.html` laadt alleen de CSS. De code kan dus niet uitgevoerd worden. Beter: de ongebruikte JS-bestanden verwijderen | Security, meldingen #2 tot #5 |
| gitleaks | `generic-api-key` | `app/appsettings.json:15` | Echt patroon, maar geen echt geheim: de key `ubk_live_...` is verzonnen voor de oefenapp en het endpoint is `example` | Er is niets mee te doen. Echte geheimen van de pipeline staan in GitHub Secrets | `.gitleaksignore` |
| OSV-Scanner | GHSA-5crp-9r3c-p9vr in Newtonsoft.Json 12.0.1 | `app/packages.lock.json` | Echt lek in de package (DoS bij diep geneste JSON), maar niet bereikbaar | De app deserialiseert geen JSON met Newtonsoft, ze gebruikt alleen `SerializeObject` bij de export. Upgraden naar 13.0.1 of hoger, uiterlijk tegen 31 januari 2027 | `osv-scanner.toml` (met `ignoreUntil`) |
