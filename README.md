# Applikationssicherheit 101 

### Herzlich willkommen zu meinem ePortfolio, das sich dem Modul "Applikationssicherheit implementieren" widmet. In diesem Portfolio nehme ich Sie mit auf eine Reise durch die Welt der Applikationssicherheit. Hier erfahren Sie mehr über meine Erfahrungen, Erkenntnisse und Fortschritte im Verlauf dieses Moduls.

#### Umsetzung Handlungsziel 1

**1.1 Erkennung von Bedrohungen:**
- Analyse und Darstellung aktueller Bedrohungen in der Applikation.
  
**1.2 Informationsbeschaffung:**
| Risikoname                               | Auswirkungen                                                                                                                                                                                                                                                                                                                                               | Gegenmaßnahmen                                                                                                                                                                                                                                                                                                                                                                                                   |
|-------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| A01:2021-Broken Access Control            | Die normalerweise von Access Control auf ihre Berechtigungsstufe beschränkte Benutzer brechen durch die Beschränkung und haben unauthorisierter Zugriff auf geschützten Daten                                                                                         | - Deny by default ( Standardmäßig den Zugriff verweigern, außer für öffentliche Ressourcen. ) <br> - Statt jedem Benutzer Zugriff auf alle Datensätze zu gewähren, Eigentumsrechte an Datensätzen durchsetzen.                                                                                                                                                                        |
| A02:2021-Cryptographic Failures          | Fehler bzw. Fehlen der Kryptographie, die oft zu sensiblen Datenexpositionen oder Systemkompromissen führen.                                                                                                                                                    | - Korrekte Implementierung von Verschlüsselungsalgorithmen. - Regelmäßige Überprüfung von kryptografischen Implementierungen. - Verwendung sicherer Verschlüsselungsschlüssel und -protokolle.                                                                                                                                                                                                                     |
| A03:2021-Injection                        | Rutscht auf den dritten Platz. 94% der Anwendungen wurden auf irgendeine Form von Injection getestet, und die 33 CWEs, die dieser Kategorie zugeordnet sind, haben die zweithäufigsten Vorkommen in Anwendungen. Cross-site Scripting ist jetzt Teil dieser Kategorie.                                                                  | - Input-Validierung durchführen, um Injection-Angriffe zu verhindern. - Verwendung von parametrisierten Abfragen in Datenbanken. - Implementierung von Content Security Policies (CSP) zur Verhinderung von Cross-site Scripting-Angriffen.                                                                                                                                                                     |
| A04:2021-Insecure Design                  | Neue Kategorie für 2021 mit Fokus auf Risiken im Zusammenhang mit Designfehlern. Schwerpunkt auf Threat Modeling, sicheren Designmustern und -prinzipien sowie Referenzarchitekturen.                                                                                                                                                                       | - Integration von Threat Modeling in den Entwicklungsprozess. - Verwendung bewährter sicherer Designmuster. - Implementierung von sicherheitsrelevanten Designprinzipien.                                                                                                                                                                                                                                    |
| A05:2021-Security Misconfiguration        | Steigt von #6 in der vorherigen Ausgabe auf. 90% der Anwendungen wurden auf irgendeine Form von Misskonfiguration getestet. Die ehemalige Kategorie für XML External Entities (XXE) ist jetzt Teil dieser Kategorie.                                                                                                                                        | - Automatisierte Konfigurationsprüfungen durchführen. - Reduzierung von unnötigen Berechtigungen und Diensten. - Regelmäßige Überprüfung der Konfigurationseinstellungen.                                                                                                                                                                                                                                      |
| A06:2021-Vulnerable and Outdated Components| Bisher als "Using Components with Known Vulnerabilities" bekannt und auf Platz #2 in der Top-10-Community-Umfrage, bewegt sich aber aufgrund von Datenanalysen auf Platz #10. Einziges Top-10-Risiko ohne Common Vulnerability and Exposures (CVEs) für die enthaltenen CWEs.                                                                               | - Regelmäßige Überprüfung und Aktualisierung von Komponenten. - Nutzung von Softwarekomponenten mit geringem Risiko. - Verwendung von Tools zur Identifizierung von bekannten Schwachstellen in Komponenten.                                                                                                                                                                                                          |
| A07:2021-Identification and Authentication Failures | Vorher als Broken Authentication bekannt und rutscht von Platz 2 ab. Enthält nun CWEs, die stärker mit Identifikationsfehlern verbunden sind.                                                                                                                                                                                                              | - Stärkung der Identifikations- und Authentifizierungsmechanismen. - Implementierung von Multi-Faktor-Authentifizierung. - Verwendung von sicheren Authentifizierungsmethoden.                                                                                                                                                                                                                               |
| A08:2021-Software and Data Integrity Failures | Neue Kategorie für 2021 mit Schwerpunkt auf Annahmen im Zusammenhang mit Softwareupdates, kritischen Daten und CI/CD-Pipelines ohne Überprüfung der Integrität.                                                                                                                                                                                      | - Verifizierung der Integrität von Softwareupdates und kritischen Daten. - Überwachung der CI/CD-Pipelines auf Integritätsprobleme. - Implementierung von Mechanismen zur Verhinderung von Insecure Deserialization.                                                                                                                                                                                                   |
| A09:2021-Security Logging and Monitoring Failures | Vorher als Insufficient Logging & Monitoring bekannt und von der Industrieumfrage (#3) hinzugefügt. Aufstieg von Platz #10. Erweitert um mehr Arten von Fehlern, schwer zu testen, nicht gut in den CVE/CVSS-Daten vertreten. Fehler in dieser Kategorie können die Sichtbarkeit, das Incident Alerting und die Forensik direkt beeinflussen. | - Implementierung von umfassendem Logging und Monitoring. - Regelmäßige Überprüfung von Logs auf Anomalien. - Nutzung von Security Information and Event Management (SIEM)-Lösungen.                                                                                                                                                                                                                              |
| A10:2021-Server-Side Request Forgery      | Von der Top-10-Community-Umfrage hinzugefügt (#1). Niedrige Inzidenzrate, aber überdurchschnittliche Testabdeckung sowie überdurchschnittliche Bewertungen für Exploit- und Impact-Potenzial. Vertreter einer Situation, in der die Sicherheitsgemeinschaft betont, dass dies wichtig ist, obwohl dies derzeit nicht durch Daten illustriert wird.               | - Implementierung von Filtern und Validierungen für benutzerseitige Anfragen. - Einsatz von Web Application Firewalls (WAF) zur Erkennung und Abwehr von Server-seitigen Request Forgery-Angriffen. - Schulung von Entwicklern für sichere Codierpraktiken im Zusammenhang mit Anfragen und Server-Antworten.                                                   |


#### Umsetzung Handlungsziel 2

**2.1 Lückenidentifikation:**
- Praktische Beispiele zur Erkennung von Sicherheitslücken.

**2.2 Gegenmaßnahmen:**
- Implementierung von Gegenmaßnahmen anhand konkreter Szenarien.

#### Umsetzung Handlungsziel 3

**3.1 Authentifizierungsmechanismen:**
- Praktische Implementierung sicherer Authentifizierungsmethoden.

**3.2 Effektive Autorisierung:**
- Umsetzung von Mechanismen für eine effektive Autorisierung im Anwendungscode.

#### Umsetzung Handlungsziel 4

**4.1 Berücksichtigung von Sicherheitsaspekten:**
- Leitfaden zur Integration von Sicherheitsüberlegungen in den Entwurfsprozess.

**4.2 Inbetriebnahme:**
- Checkliste für die Sicherheitsüberprüfung während der Inbetriebnahme.

#### Umsetzung Handlungsziel 5

**5.1 Generierung von Audit-Informationen:**
- Methoden zur Erzeugung von relevanten Informationen für Auditing und Logging.

**5.2 Auswertungen und Alarme:**
- Definition und Implementierung von Auswertungen sowie Alarmen bei sicherheitsrelevanten Ereignissen.
