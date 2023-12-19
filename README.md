# ⛑ Applikationssicherheit 1️⃣0️⃣1️⃣

### Herzlich willkommen zu meinem ePortfolio, das sich dem Modul "Applikationssicherheit implementieren" widmet. In diesem Portfolio nehme ich Sie mit auf eine Reise durch die Welt der Applikationssicherheit. Hier erfahren Sie mehr über meine Erfahrungen, Erkenntnisse und Fortschritte im Verlauf dieses Moduls.

#### Umsetzung Handlungsziel 1

**1.1 Häufige Bedrohungen:**

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

Nebst der Top 10 Liste von OWASP gibt es sämtliche weiter Hilfsmittle zur Sicherung von Applikationen darunter Cheat Sheets, welche als konkrete Anleitung bzw. Checkliste zu verwenden ist, um strategisch Sicherheitslücken abzudecken. 
<br>
**1.2 Einordnung der Bedrohungen:**
Das Abarbeiten der genannter Cheat sheets ist eine sehr zeitaufwändige Aufgabe, welcher trotz der Wichtigkeit, in gewissen Fällen nicht zu 100% durchgeführt werden kann. 
In solchen Fällen wo man seine Effizienz erhöhen möchte, ist es wichtig erkennen zu können welche Bedrohungen einem am ehesten betrifft und welche am gravierendsten sind. Diese sollten bevorzugt werden, um eine Grundlegende Sicherheitszustand zu erreichen.
Eine Analyse der Bedrohungen mit einem Likelihood-Impact Diagramm kann verwendet werden, um einen Prioritätsplan zu erzeugen.

**1.3 Erfüllung des Handlungsziels:**
Mein Artefakt zeigt anhand meiner selbstgeschriebenen Beschreibungen der Bedrohungen, dass ich über ein gutes Verständnis der Auswirkungen der, von OWASP ernannten häufigsten Cyber-Angriffen, verfüge und dass ich mögliche Massnahmen kenne. 
Um dies jedoch noch weiter zu zeigen, wären konkrete Beispiele von Vorteil gewesen. Jedoch, weil eine detailiertere Behandlung der meisten Bedrohungen in den nächsten Handlungszielen mit konkreten Beispielen belegt werden, wäre dies ein wenig überflüssig im HZ1. 
Das Erkenntnis, dass Bedrohungen nicht in allen Fällen gleich sind und dass man Bedrohungen einordnen sollte, ist ein wichtiger Bestandteil des Handlungsziels, welcher ich erläutert habe.  

#### Umsetzung Handlungsziel 2

**2.1 Lückenidentifikation:**
Hier haben wir einen klassischen Fall der SQL Injection. In diesem LoginController welches für den Login in eine Web.Applikation verwendet wird, wird ein String für den Request and eine SQL Datenbank verwendet. Bestandteile dieses Strings werden direkt vom Benutzer über die Webseite eingegeben. Da keine Sicherheitsbarrieren vorhanden sind, kann der Benutzer oder in diesem Fall der Hacker SQL Syntax verwenden, um den Login zu knacken. 
Hier sieht man wo ein String als Request verwendet wird: <br>
![InsecureApp](https://github.com/buDget01/BlattmannPatrick-LB183/assets/89085636/da137e2c-fb46-4a86-8438-a45bff9ef194) <br>
Das Missbrauchen dieser Lücke passiert auf der Webseite im Login Eingabefeld: <br>
![Website](https://github.com/buDget01/BlattmannPatrick-LB183/assets/89085636/3dd013b5-79e1-430e-a297-4cd3149c8938) <br>
Intern sieht dies in der Applikation dann so aus: <br>
![Code1](https://github.com/buDget01/BlattmannPatrick-LB183/assets/89085636/f8c8f737-3bb9-4dd4-a538-f0f49a4c8729) <br>


Mit einer einfachen Eingabe von ``` ' OR '1'='1' -- ``` wird das Passwortfeld zu einem SQL-Kommentar gemacht ("--" = SQL Kommentar Syntax) und die Abfrage immer wahr gemacht ('1'='1' ist immer wahr)
So kommt der Unberechtigter ohne Username oder Passwort ganz einfach in die Kernapplikation rein, wo sämtliche Schaden angerichtet oder sensible Daten veröffentlicht werden können. 



**2.2 Gegenmaßnahmen:**
Um diese Sicherheitslücke verschwinden zu lassen gibt es eine ganz einfache Lösung. Nämlich, wenn man statt der direkten Request mit SQL Syntax, eine paramatisierte Abfrage verwendet. <br>
```csharp
 string sql = "SELECT * FROM Users WHERE username = {0} AND password = {1}";

 User? user = _context.Users.FromSqlRaw(sql, request.Username, request.Password).FirstOrDefault();
 if (user == null)
 {
     return Unauthorized("Login failed");
 }
 return Ok(user);
```
<br> 
Somit wird das direkte Einschreiben vom Benutzer in den Request verhindert. 

**2.3 Erfüllungs des Handlungsziels**
Mit meinem Artifakt habe ich ein Beispielprogramm verwendet, welcher Sicherheitslücken hat. Diese habe ich erkannt und anhand meines Wissens dem SQL Injektion zugeordnet. Meine Screenshots zeigen klar, dass ich die Funktion des Codes und die Wirkung der Ausnutzung dessen verstanden habe. Somit kann ich Sicherheitslücken und ihre Ursachen in einer Applikation erkennen. Um mein Wissen noch weiter vorzuzeigen, hätte ich noch weitere Beispiele mit anderen Sicherheitslücken aufzeigen, jedoch wäre dies sehr Zeitaufwändig. 
Das Vorhande zeigt aber die Grundlegende Erfüllung des Handlungsziels. 
Zusätzlich habe ich in einem weiteren Artefakt, in Form eines kurzen Codes gezeigt, dass ich fähig bin Massnahmen gegen Sicherheitslücken zu erstellen und diese zu implementieren. Da wären ebenfalls weitere Beispiele noch schön, jedoch ist die Erfüllung des handlungsziels gegeben. 

#### Umsetzung Handlungsziel 3

**3.1 Authentifizierungsmechanismen:**
Die Authentifizierung ist für uns digital natives etwas, was wir seit dem ersten Kontakt mit dem Internet kennen. Praktisch jede Webseite, welche mögliche sensible Daten enthält braucht eine Authentifizierung. 
Die verbreiteste Methode der Authentifizierung ist mit einem Username/einer Mailadresse in Kombination mit einem Passwort. Dies dient zur Überprüfung der Identität des Benutzers durch Wissensnachweis. 
Im Artefakt des Handlungsziels 2 habe ich diese Methode bereits aufgezeigt. In der Beispielsapplikation wird ein Login mit Username und Passwort verwendet, um abzuchecken, ob der Benutzer über das nötige Wissen verfügt, um Zugang zur Webseite zu bekommen. 
Der Login aus dem Beispiel kann sehr gut in anderen Projekt eingesetzt werden und ist recht Standard. 


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
