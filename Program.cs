using Microsoft.EntityFrameworkCore;
using TodoApi;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

var host = Environment.GetEnvironmentVariable("DB_HOST");
var port = Environment.GetEnvironmentVariable("DB_PORT") ?? "3306";
var database = Environment.GetEnvironmentVariable("DB_NAME");
var user = Environment.GetEnvironmentVariable("DB_USER");
var password = Environment.GetEnvironmentVariable("DB_PASSWORD");

// Try to get connection string from configuration (appsettings) first
string connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    ?? builder.Configuration["ConnectionStrings:DefaultConnection"];

// If environment variables are provided, prefer building the connection string from them
if (!string.IsNullOrWhiteSpace(host))
{
    var missingEnv = new List<string>();
    if (string.IsNullOrWhiteSpace(database)) missingEnv.Add("DB_NAME");
    if (string.IsNullOrWhiteSpace(user)) missingEnv.Add("DB_USER");
    if (string.IsNullOrWhiteSpace(password)) missingEnv.Add("DB_PASSWORD");

    if (missingEnv.Count > 0)
    {
        throw new InvalidOperationException($"DB_HOST is set, but missing required environment variables: {string.Join(", ", missingEnv)}. Set DB_NAME, DB_USER, DB_PASSWORD too.");
    }

    connectionString = $"server={host};port={port};database={database};user={user};password={password};SslMode=Required;";
    Console.WriteLine("Using DB connection from environment variables (Render style).");
    Console.WriteLine($"DB_HOST={host};DB_NAME={database};DB_USER={user};DB_PORT={port}");
}
else
{
    Console.WriteLine("Using DB connection from configuration DefaultConnection.");
    if (!string.IsNullOrWhiteSpace(connectionString))
    {
        Console.WriteLine("Loaded DefaultConnection from configuration.");
    }
}

if (string.IsNullOrWhiteSpace(connectionString))
{
    throw new InvalidOperationException("No database connection string configured. Set ConnectionStrings__DefaultConnection or DB_HOST/DB_NAME/DB_USER/DB_PASSWORD.");
}

if (connectionString.IndexOf("name=", StringComparison.OrdinalIgnoreCase) >= 0)
{
    throw new InvalidOperationException($"Invalid MySQL connection string: unsupported option 'name'. Connection string value: '{connectionString}'. Remove 'name=...' from the connection string.");
}

var serverVersion = new MySqlServerVersion(new Version(8, 0, 36));
// זה מבטל כל הגדרה אוטומטית ומשתמש רק במה שאנחנו בונים ידנית
builder.Services.AddDbContext<ToDoDbContext>(options =>
{
    var serverVersion = new MySqlServerVersion(new Version(8, 0, 36));
    options.UseMySql(connectionString, serverVersion);
}, ServiceLifetime.Scoped); // הוספת Scope מוודאת שה-Context נוצר מחדש בכל בקשה

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddCors(options =>
    options.AddPolicy("AllowAll", policy =>
        policy.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader()));

var key = Encoding.ASCII.GetBytes("ThisIsMyVerySecretKeyForJwt1234567890");

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateIssuer = false,
            ValidateAudience = false
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

try
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<ToDoDbContext>();
    db.Database.EnsureCreated();
}
catch (Exception ex)
{
    Console.WriteLine($"Database initialization failed: {ex.Message}");
}

app.UseSwagger();
app.UseSwaggerUI();
app.UseCors("AllowAll");
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => "Server is running!");

app.MapGet("/items", async (ToDoDbContext db) =>
    await db.Items.ToListAsync());

app.MapPost("/items", async (ToDoDbContext db, Item item) =>
{
    db.Items.Add(item);
    await db.SaveChangesAsync();
    return Results.Created($"/items/{item.Id}", item);
}).RequireAuthorization();

app.MapPut("/items/{id}", async (ToDoDbContext db, int id, Item inputItem) =>
{
    var item = await db.Items.FindAsync(id);
    if (item is null) return Results.NotFound();
    item.Name = inputItem.Name;
    item.IsComplete = inputItem.IsComplete;
    await db.SaveChangesAsync();
    return Results.NoContent();
}).RequireAuthorization();

app.MapDelete("/items/{id}", async (ToDoDbContext db, int id) =>
{
    if (await db.Items.FindAsync(id) is Item item)
    {
        db.Items.Remove(item);
        await db.SaveChangesAsync();
        return Results.Ok(item);
    }
    return Results.NotFound();
}).RequireAuthorization();

app.MapPost("/login", (User user, ToDoDbContext db) =>
{
    var dbUser = db.Users.FirstOrDefault(u => u.Username == user.Username && u.Password == user.Password);
    if (dbUser == null) return Results.Unauthorized();

    var tokenHandler = new JwtSecurityTokenHandler();
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[] { new Claim("id", dbUser.Id.ToString()) }),
        Expires = DateTime.UtcNow.AddDays(7),
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
    };
    var token = tokenHandler.CreateToken(tokenDescriptor);
    return Results.Ok(new { token = tokenHandler.WriteToken(token) });
});

app.MapPost("/register", async (ToDoDbContext db, User user) =>
{
    var existingUser = await db.Users.FirstOrDefaultAsync(u => u.Username == user.Username);
    if (existingUser != null)
        return Results.BadRequest("משתמש זה כבר קיים במערכת");

    db.Users.Add(user);
    await db.SaveChangesAsync();
    return Results.Ok(new { message = "User registered successfully" });
});

app.Run();