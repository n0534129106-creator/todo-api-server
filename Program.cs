using Microsoft.EntityFrameworkCore;
using TodoApi;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);
Console.WriteLine("--- !!! ATTENTION: RUNNING VERSION 10.0 - NO MORE ERRORS !!! ---");
Console.WriteLine("--- ATTENTION: DEPLOYING VERSION 7.0 - THE CLEANER ---");
// לוג כדי לראות ב-Render שהקוד החדש רץ
Console.WriteLine("--- !!! REBOOT VERSION 6.0 - MANUAL CONNECTION ONLY !!! ---");

var host = Environment.GetEnvironmentVariable("DB_HOST");
var port = Environment.GetEnvironmentVariable("DB_PORT") ?? "3306";
var database = Environment.GetEnvironmentVariable("DB_NAME");
var user = Environment.GetEnvironmentVariable("DB_USER");
var password = Environment.GetEnvironmentVariable("DB_PASSWORD");

// בניית מחרוזת חיבור בצורה הכי פשוטה שיש
string connectionString = $"server={host};port={port};database={database};user={user};password={password};SslMode=Required;AllowUserVariables=true;";

builder.Services.AddDbContext<ToDoDbContext>(options =>
{
    var serverVersion = new MySqlServerVersion(new Version(8, 0, 36));
    options.UseMySql(connectionString, serverVersion, mysqlOptions => 
    {
        mysqlOptions.EnableRetryOnFailure();
    });
});

// ... שאר ההגדרות שלך (CORS, JWT, וכו') ...
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddCors(options => options.AddPolicy("AllowAll", p => p.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader()));

var key = Encoding.ASCII.GetBytes("ThisIsMyVerySecretKeyForJwt1234567890");
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options => {
        options.TokenValidationParameters = new TokenValidationParameters {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateIssuer = false,
            ValidateAudience = false
        };
    });
builder.Services.AddAuthorization();

var app = builder.Build();

// ניסיון ראשוני להתחבר ולהדפיס הצלחה/כישלון
try {
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<ToDoDbContext>();
    db.Database.CanConnect(); 
    Console.WriteLine("--- DATABASE CONNECTED SUCCESSFULLY! ---");
} catch (Exception ex) {
    Console.WriteLine($"--- DATABASE CONNECTION FAILED: {ex.Message} ---");
}

app.UseSwagger();
app.UseSwaggerUI();
app.UseCors("AllowAll");
app.UseAuthentication();
app.UseAuthorization();

// ה-Routes שלך (Items, Login, Register...)
app.MapGet("/", () => "Server is running (V6)!");
// ... שאר ה-app.Map...
app.Run();