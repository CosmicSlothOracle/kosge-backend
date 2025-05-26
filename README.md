# kosge-backend

## Ziel

Dieses Backend dient als zentrale API für die Kosge-Website. Es ermöglicht:

- Verwaltung von Teilnehmerdaten (Events)
- Verwaltung von Slideshow- und Programm-Bildern (Austausch der Bild-URLs)
- Admin-Login mit festem Passwort (JWT-basiert)
- Bereitstellung von APIs für das Frontend (z.B. für Teilnahmeformulare, Banner/Slideshow, Traffic-Statistik)

## Wichtige Endpunkte

### User-APIs

- `POST /api/participants` – Teilnahme an Event (Name, E-Mail, Nachricht, Event-ID)
- `GET /api/banners` – Liste der aktuellen Banner/Slideshow-URLs

### Admin-APIs (JWT-geschützt)

- `POST /api/login` – Admin-Login, gibt JWT zurück
- `GET /api/participants` – Teilnehmerdaten abrufen
- `POST /api/banners` – Bild-Link ersetzen/hinzufügen (z.B. storj-Link)
- `DELETE /api/banners/<index>` – Bild-Link entfernen

## Bildverwaltung

Die Slideshow/Programm-Bilder werden als Liste von URLs gespeichert. Im Admin-Panel kann ein Bild-Link durch einen neuen ersetzt werden. Die Änderung ist sofort im Frontend sichtbar.

## Deployment

Empfohlen: Render.com (kostenloses Python-Backend)

---

Weitere Details folgen in den jeweiligen Modulen und im Quellcode.
