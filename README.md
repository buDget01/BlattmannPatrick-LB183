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

**2.3 Erfüllungs des Handlungsziels:**

Mit meinem Artifakt habe ich ein Beispielprogramm verwendet, welcher Sicherheitslücken hat. Diese habe ich erkannt und anhand meines Wissens dem SQL Injektion zugeordnet. Meine Screenshots zeigen klar, dass ich die Funktion des Codes und die Wirkung der Ausnutzung dessen verstanden habe. Somit kann ich Sicherheitslücken und ihre Ursachen in einer Applikation erkennen. Um mein Wissen noch weiter vorzuzeigen, hätte ich noch weitere Beispiele mit anderen Sicherheitslücken aufzeigen, jedoch wäre dies sehr Zeitaufwändig. 
Das Vorhande zeigt aber die Grundlegende Erfüllung des Handlungsziels. 
Zusätzlich habe ich in einem weiteren Artefakt, in Form eines kurzen Codes gezeigt, dass ich fähig bin Massnahmen gegen Sicherheitslücken zu erstellen und diese zu implementieren. Da wären ebenfalls weitere Beispiele noch schön, jedoch ist die Erfüllung des handlungsziels gegeben. 

#### Umsetzung Handlungsziel 3

**3.1 Authentifizierungsmechanismen:**

Die Authentifizierung ist für uns digital natives etwas, was wir seit dem ersten Kontakt mit dem Internet kennen. Praktisch jede Webseite, welche mögliche sensible Daten enthält braucht eine Authentifizierung. 
Die verbreiteste Methode der Authentifizierung ist mit einem Username/einer Mailadresse in Kombination mit einem Passwort. Dies dient zur Überprüfung der Identität des Benutzers durch Wissensnachweis. 
<br>
Im Artefakt des Handlungsziels 2 habe ich diese Methode bereits aufgezeigt. In der Beispielsapplikation wird ein Login mit Username und Passwort verwendet, um abzuchecken, ob der Benutzer über das nötige Wissen verfügt, um Zugang zur Webseite zu bekommen. 
Der Login aus dem Beispiel kann sehr gut in anderen Projekt eingesetzt werden und ist recht Standard. 
<br>
Diese Art und Weise der Authentifizierung ist in den meisten Fällen ausreichend, jedoch wäre eine 2-Faktor Authentifizierung, welcher auf eine andere Art von Identitätsnachweis beruht, ideal. Da gibt es sämtliche Optionen: 
- Besitz des Stammgeräts: SMS-Code, Authenticator Apps etc.
- Zugang zu einer bereits bekannter Mailadresse
- Biologische Nachweise: Fingerabdruck, Gesichtserkennung,
- Schlüssel in Form von Physische Secure Key Geräte


**3.2 Effektive Autorisierung:**
Autorisierung klingt zwar ähnlich wie die Authentifizierung und wird auch oft vertauscht. Es gibt jedoch einen klaren Unterschied zwischen den Beiden. Bei der Authentifizierung handelt es sich um die Wer-Frage, im Gegensatz zur Autorisierung wo die Was-Frage behandelt. Genauer gesagt wird mit der Autorisierung geregelt was der eingeloggter Benutzer in der Web-Applikation machen darf. 
<br>
Der Grundkonzept dieses Ablaufs sieht wie folgt aus: Der Benutzer loggt sich in die Webapplikation ein. Diese Benutzerdaten werden anschliessend an den Server gesendet und wird dort in der Session gespeichert. Dieser Session hat eine ID mit dazugebundenen Rechten. Die Session ID wird an den Browser zurückgegeben und bei jedem weiteren Request wird diese Session ID mitgegeben, um die Autorisierung zu durchführen, also quasi zu schauen ob der Benutzer die nötigen Rechte besitzt. 
<br>
Es gibt jedoch eine effizientere Methode die Autorisierung durchzuführen. Nämlich mit JWT oder JSON Web Tokens. Der Prozess ist sehr ähnlich mit kleinen Unterschieden. Anstatt, dass die Rechte auf dem Server gespeichert werden, beinhaltet der JWT den User Eigenschaften darunter seine Rechte (diese Eigenschaften auch genannt "Claims") in Verschlüsselter Form mit einer dazugehörigen Signatur. Im Falle, dass ein Unberechtigter die Rechte auf dem JWT zu verändern versucht, wird die Signatur sich verändern und vom Server als ungültig erkannt werden. 
<br> 
Hier ist die Implementierung dieser in der Beispielapplikation vom vorherigen Handlungsziel: <br>
Login Controller:
```csharp
namespace M183.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly NewsAppContext _context;
/// Hier der geheime Schlüssel
        private readonly string _jwtSecret = "Secretkey101";

        public LoginController(NewsAppContext context)
        {
            _context = context;
        }

        /// <summary>
        /// Login a user using password and username
        /// </summary>
        /// <response code="200">Login successfull</response>
        /// <response code="400">Bad request</response>
        /// <response code="401">Login failed</response>

        /// Patrick Tri My Blattmann
        [HttpPost]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(401)]
        public ActionResult<User> Login(LoginDto request)
        {
            ///login Code von Handlungsziel 2

///Neu ab hier --------------------------------
            var token = GenerateJwtToken(user);

            return Ok(user);
        }

        private string GenerateJwtToken(User user)
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), 
                new Claim(JwtRegisteredClaimNames.NameId, user.Id.ToString()), 
                // Weitere Claims hinzufügen, je nach Bedarf
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSecret));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                issuer: "your-issuer", 
                audience: "your-audience", 
                claims: claims,
                expires: DateTime.Now.AddDays(1), 
                signingCredentials: credentials
            );

            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

            return tokenString;
        }
    }
}

```
<br>
Program.cs:

```csharp

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<NewsAppContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("SongContext")));

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "SwaggerAnnotation", Version = "v1" });
    c.IncludeXmlComments(Path.Combine(System.AppContext.BaseDirectory, "SwaggerAnnotation.xml"));
});

///Hier der geheime Schlüssel
var key = Encoding.ASCII.GetBytes("Secretkey101"); 

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateIssuer = true,
            ValidIssuer = "your-issuer", // Hier Ihren Aussteller einfügen
            ValidateAudience = true,
            ValidAudience = "your-audience", // Hier Ihr Publikum einfügen
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        };
    });

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
```

**3.3 Erfüllung des Handlungsziels:**
Die prägnante Zusammenfassung der Funktion und der Möglichkeiten der Authentifizierung zeigt, dass ich das Thema gut verstehe. Zudem habe ich schon im Handlungsziel 2 erklärt wie der Login Funktioniert und welche Auswirkungen ein guter Login auf die Sicherheit der Applikation hat. 
Mit dem Vergleich des JWT-Methode mit der traditionellen Methode, zeige ich auf, dass ich die Funktionsweise der Authentisierung gut begriffen habe. Die Implementierung im Beispielprogramm soll auch zeigen, dass ich den theoretischen Prozess auch in einem Programm umsetzen kann. 
Als Verbesserung hätte ich mehr Kommentare im Code hinterlassen sollen, um zu zeigen dass ich genau verstehe was gemacht wird. 


#### Umsetzung Handlungsziel 4

**4.1 Berücksichtigung von Sicherheitsaspekten:**
Die zahlreichen Sicherheitsaspekten die zu beachten sind, können zum Teil überfordernd sein. Aus diesem Grunde habe ich aus den wichtigsten Punkten eine Grafik erstellt. Diese Punkte sind alle Teil der defensiven Programmierung, welche für das sichere Entwerfen, Implementieren und Inbetriebnehmen einer Webapplikation sorgt. 
<br>
![Mindmap](https://github.com/buDget01/BlattmannPatrick-LB183/assets/89085636/539ff999-7b14-4a4e-bcd9-06a0f1f3a275)


**4.2 Inbetriebnahme:**
Als Beispiel für eine praktische Umsetzung eines dieser Aspekten habe ich versucht 2-Faktor-Authentifizierung zu implementieren. Die 2-Faktor-Authentifizierung wäre eine sehr starke Barriere gegen den sogenannten "Human Factor", denn auch wenn der Username und das Passwort durch einem Leak auf ende des Users in den falschen Händen gelangen würde, hätten die Unbefugten grosse Schwierigkeiten weiterzukommen. 
Ich habe mich auf die SMS-Variante der 2-Faktor-Authentifizierung entschieden:

```csharp

 public ActionResult<User> Login(LoginDto request)
 {
     if (request == null || request.Username.IsNullOrEmpty() || request.Password.IsNullOrEmpty())
     {
         return BadRequest();
     }

     string sql = "SELECT * FROM Users WHERE username = {0} AND password = {1}";

     User? user = _context.Users.FromSqlRaw(sql, request.Username, request.Password).FirstOrDefault();
     if (user == null)
     {
         return Unauthorized("Login failed");
     }

///Ab hier wird die 2-Faktor-Authentifizierung umgesetzt
///Ein One Time Password wird generiert und an eine beim sign in gespeicherte Telefonnummer geschickt
      string otp = GenerateOTP();
SaveOTPForUser(user.Id, otp);

SMSService.SendSMS(user.PhoneNumber, $"Ihr Einmalkode für die 2-Faktor-Authentifizierung: {otp}");

     var token = GenerateJwtToken(user);
///Der User wird weitergeleitet zum Eingabefeld für den OTP
return RedirectToAction("EnterOTP", new { userId = user.Id });

     return Ok(user);
 }

///Hier ist die Methode welcher für die Authentifizierung der OTP zuständig ist
public ActionResult EnterOTP(int userId, string enteredOTP)
{
    // Überprüfen Sie den eingegebenen Einmalkode mit dem gespeicherten Wert
    var savedOTP = GetSavedOTPForUser(userId);

    if (enteredOTP != savedOTP)
    {
        return Unauthorized("Falscher Einmalkode");
    }

    // Wenn der Einmalkode korrekt ist, generieren Sie das JWT-Token und führen Sie die üblichen Schritte fort
    var user = GetUserById(userId);
    var token = GenerateJwtToken(user);

    // Rückgabe des Benutzers oder einer anderen Bestätigung
    return Ok(user);
}

```
<br>
In diesem Code inbehalten sind die grundlegenden Bausteine einer Zwei-Faktoren-Authentifizierung mittels SMS. Dazu müsste das Frontend bearbeitet, sowie einen SMS-Service auf die Beine gestellt werden.
<br>

**4.3 Erfüllung des Handlungsziels**
Nach all dem Code fand ich es noch wichtig die grosse Menge an Information zu den Sicherheitsaspekten in einer anderen Darstellung als reiner Text oder einer Tabelle einzuprägen. Die Grafik eignet sich gut, um die Aspekten zuzuordnen und die Sicherheitsbewusste Entwicklung zu strukturieren. 
Nichtsdestotrotz wollte ich noch eines der Aspekten mit Code belegen. Die Auswahl der 2-Faktor-Authentifizierung war gewollt, denn dies wird langsam zu Best-Practice um Zugriffsattacken aufzuhalten. 
Besser wäre wenn ich dies vollständig umsetzen könnte inklusive Frontend und SMS-Service, jedoch wäre diese Umsetzung von sehr grosser Aufwand gewesen. Den Ausbau der Beispielapplikation genügt zur Verständnis der Logik und des Zusammenhangs. 

#### Umsetzung Handlungsziel 5

**5.1 Generierung von Audit-Informationen:**
Zu den Sicherheitsaspekten gehören auch Logging und Monitoring. Diese werde ich im Beispiel anhand einer Klasse praktisch umsetzen: 

Im Program.cs zuzufügen:
```csharp
///Using... statements
///Builder von vorhin

builder.Host.ConfigureLogging(logging =>
{
///Die Vorgänge sind dem Namen entsprechend
    logging.ClearProviders(); 
    logging.AddConsole();
    logging.AddDebug();
});

```

In den Controllers einzufügen:

```csharp
 public class LoginController : ControllerBase
 {

 private readonly ILogger<MyController> _logger;

    public MyController(ILogger<MyController> logger)
    {
        _logger = logger;
    }


///weiterer Code wie ActionResult<User> Login(LoginDto request)...

///dependency injection im [HttpPost]
_logger.LogInformation("POST request successfull."); ///Die Logging-Nachricht von Fall zu Fall zu verändern
_logger.LogError("An error occurred: {ErrorMessage}", ex.Message); ///Bei Error sollte auch ein Error geloggt werden nicht nur eine Information


```

Mit den Zusatz dieser Code-Abschnitte besteht die Option wo nötig eine Nachricht/ein Error zu loggen. Mit Monitoring kann man dann seine Applikation auf allfälligen Angriffen überwachen. Um dies effizient zu machen sollte das Logging nach ausgebaut werden, sodass ereignisse spezifischer geloggt werden. So kann man besser auffassen wo, was geschieht und wie man entgegenwirken kann. 


**5.2 Erfüllung des Handlungsziels**
Dieser Artefakt liess mich die Funktion von Logging genauer anschauen. Es ist wichtig nicht nur zu erkennen, wofür Logging wichtig ist, sondern auch wo genau Logging implementiert werden soll. In welchen Controllern und wie genau die Loggingnachrichten sein sollten. 
Mein Logger ist relativ simple aufgebaut und kann auch ohne Porblem in weiteren Applikationen verwendet werden. Um einen ausführlichen Loggingsystem zu erstellen muss man den am jeweiligen Programm besser anpassen. Ich habe in diesem Artefakt nicht jeweils in allen Controllern den Logger angepasst, sondern einen Generellen aufbau festgelegt, welcher in den Controllern eingesetzt werden kann. Mit der Herstellung dieses Artefakts habe ich jedoch das Handlungsziel grösstenteils erreicht. 

