# Applikationssicherheit 101 

### Herzlich willkommen zu meinem ePortfolio, das sich dem Modul "Applikationssicherheit implementieren" widmet. In diesem Portfolio nehme ich Sie mit auf eine Reise durch die Welt der Applikationssicherheit. Hier erfahren Sie mehr über meine Erfahrungen, Erkenntnisse und Fortschritte im Verlauf dieses Moduls.

#### Umsetzung Handlungsziel 1

**1.1 Erkennung von Bedrohungen:**

Es existieren fast endlose Taktiken welche Hacker verwenden können, um Sicherheitslücken in Applikationen auszunutzen. 
<br>
Unser job als Entwickler besteht darin diese Lücken abzudecken, um die Angriffe der Hackern vorzubeugen. 
Da es eben so viele Angriffsarten gibt und es nahezu unmöglich ist alle zu vermeiden, ist es wichtig zu kennen welche am häufigsten verwendet werden.
<br>
Mithilfe der Top 10 Liste der OWASP kann man sicherstellen, dass die häufigsten und auch gefährlichsten Cyber-Attacken vermieden werden können. 
Um die benannten Risiken der OWASP besser zu verstehen und auch in Zukunft bei der Entwicklung zu berücksichtigen, habe ich eine Tabelle mit selbst erklärten Auswirkungen und einige der zugehörigen Massnahmen erstellt. 
  
| Risiko                             | Auswirkungen / Einsatz                                                                                                                                                                                                                                                                                                                                               | Massnahmen                                                                                                                                                                                                                                                                                                                                                                                                   |
|-------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| A01 -Broken Access Control            | Die normalerweise von Access Control auf ihre Berechtigungsstufe beschränkte Benutzer brechen durch die Beschränkung und haben unauthorisierter Zugriff auf geschützten Daten                                                                                         | - Deny by default ( Standardmäßig den Zugriff verweigern, außer für öffentliche Ressourcen. ) <br> - Statt jedem Benutzer Zugriff auf alle Datensätze zu gewähren, Eigentumsrechte an Datensätzen durchsetzen.   |
| A02 -Cryptographic Failures          | Fehler bzw. Fehlen der Kryptographie, die oft zu sensiblen Datenexpositionen oder Systemkompromissen führen.                                                                                                                                                    | - Verschlüsselungsalgorithmen korrekt implementieren. <br> - Regelmässige die kryptografischen Implementierungen überprüfen. <br> - Sichere Verschlüsselungsschlüssel und -protokolle verwenden.                                                                                                                                                                                                                     |
| A03 -Injection                        | Nicht vertrauenswürdige Daten werden in eine Anwendung einfügt, um böswillige Befehle zu erzwingen  | - Sichere API verwenden um den Interpretationsprogramm zu umgehen (bei SQL zum Beispiel) <br> - Escape Syntax für Interpreter verwenden.                                                                                                                                                                     |
| A04 -Insecure Design                  | Im design grundlegende Fehler in Bezug auf Sicherheit (bspw. beim Login kein Passwort verlangen) | - Threat Modeling im Entwicklungsprozess integrieren. <br> - Sicherheitsrelevanten Designprinzipien (bewährte Designmuster) implementieren.                                                                                                                                                                                                                                    |
| A05 -Security Misconfiguration        | Bestehende Sicherheitsmassnahmen werden falsch konfiguriert (Berechtigungen zu freizügig konfiguriert / Unnötig Funktionen bestehen / Standardpasswörter sind aktiviert) | - Unnötige Berechtigungen und Diensten reduzieren. <br> - Regelmäßige Überprüfung der Konfigurationseinstellungen.                                                                                                                                                                                                                                      |
| A06 -Vulnerable and Outdated Components| Veraltete/unsichere Komponenten werden verwendet (viele Schwachstellen) | - Regelmässige Überprüfung und Aktualisierung von Komponenten. <br> - Softwarekomponenten mit geringem Risiko verwenden (offizielle Quellen / regelmässige Patches).                                                                                                                                                          |
| A07 -Identification and Authentication Failures | Automatisierte Angriffe wie Brute-Force-Angriffe werden nicht vorgebeugt & unsorgfältiger Umgang mit Passwörtern | - Multifaktor-Authentifizierung verwenden. <br> - Vorgaben für Passwörter festlegen. <br> - Wiederholte Login-Versuche einschränken.                                                                                                                                                                                                                               |
| A08 -Software and Data Integrity Failures | Automatisierte Aktualisierung beinhaltet keine Integritätsprüfung & ermöglicht somit die Publizierung von Anwendungen mit Sicherheitslücken. | - Die Integrität von Softwareupdates und kritischen Daten verifizieren. <br> - CI/CD-Pipelines auf Integritätsprobleme bewachen.                                                                                                                                                                                                |
| A09 -Security Logging and Monitoring Failures | Erreignisse werden nicht gelogged bzw. überwacht | - Umfassend Loggen und Bewachen. <br> - Logs auf Anomalien überprüfen. <br> - Security Information and Event Management (SIEM)-Lösungen verwenden.                                                                                                                                                                                                                              |
| A10 -Server-Side Request Forgery      | HTTP wird verwendet um ungesicherte Daten anzufordern | - Filtern und Validierungen für benutzerseitige Anfragen verwenden. <br> - Web Application Firewalls (WAF) einsetzen. <br> - Keine rohe Daten an Benutzern senden                                                |


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
