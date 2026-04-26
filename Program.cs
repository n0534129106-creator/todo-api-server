using Microsoft.EntityFrameworkCore;
using TodoApi;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
var builder = WebApplication.CreateBuilder(args);
var connectionString = builder.Configuration.GetConnectionString("ToDoDB");
builder.Services.AddEndpointsApiExplorer();//לסווגר
builder.Services.AddSwaggerGen();
//ה cors
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyOrigin()   // מאפשר לכל כתובת לגשת
             .AllowAnyMethod()   // מאפשר את כל הפעולות (GET, POST, וכו')
            .AllowAnyHeader();  // מאפשר את כל סוגי ה-Headers
    });
});
//mysql חיבור ל
builder.Services.AddDbContext<ToDoDbContext>(options =>
    options.UseMySql(connectionString, ServerVersion.AutoDetect(connectionString)));


// 1.   הגדרת המפתח הסודי - ה"מפתח" שבאמצעותו השרת חותם על הטוקנים ומאמת אותם
var key = Encoding.ASCII.GetBytes("ThisIsMyVerySecretKeyForJwt1234567890"); 

// 2. הוספת שירותי אימות (Authentication) לפרויקט
builder.Services.AddAuthentication(options =>
{
    // הגדרת JWT כשיטה ברירת המחדל לזיהוי משתמשים
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;//חפש בheader
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;//אם לא תקין החזרה של 401
})
.AddJwtBearer(options =>
{
    // הגדרת החוקים לאימות הטוקן שמגיע מהקליאנט
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true, // בדיקה שהטוקן נחתם עם המפתח הסודי שלנו
        IssuerSigningKey = new SymmetricSecurityKey(key), // המפתח שבו משתמשים לאימות
        ValidateIssuer = false, //  לא בודקים מי הנפיק את הטוקן
        ValidateAudience = false //  לא בודקים למי יועד הטוקן
    };
});

// 3. הוספת שירותי הרשאות (Authorization) - מאפשר לנעול נתיבים ספציפיים
builder.Services.AddAuthorization();
var app = builder.Build();
    app.UseCors("AllowAll");
app.UseAuthentication(); // חובה! בודק "מי המשתמש" לפי הטוקן
app.UseAuthorization();  // חובה! בודק "מה מותר למשתמש"

// ... ואז מגיעים ה-MapGet וה-MapPost

// יצירת הסווגר רק אם הסביבה היא לפיתוח
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();

}

// 1. שליפת כל המשימות
// 1. שליפת משימות - פתוח לכולם
app.MapGet("/items", async (ToDoDbContext db) =>
    await db.Items.ToListAsync());

// 2. הוספת משימה - נעול! (מופיע רק פעם אחת עם ה-RequireAuthorization)
app.MapPost("/items", async (ToDoDbContext db, Item item) =>
{
    db.Items.Add(item);
    await db.SaveChangesAsync();
    return Results.Created($"/items/{item.Id}", item);
}).RequireAuthorization(); 

// 3. עדכון משימה - נעול!
app.MapPut("/items/{id}", async (ToDoDbContext db, int id, Item inputItem) =>
{
    var item = await db.Items.FindAsync(id);
    if (item is null) return Results.NotFound();
    item.Name = inputItem.Name;
    item.IsComplete = inputItem.IsComplete;
    await db.SaveChangesAsync();
    return Results.NoContent();
}).RequireAuthorization();

// 4. מחיקת משימה - נעול!
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

// 5. לוגין - חייב להישאר פתוח!
app.MapPost("/login", (User user, ToDoDbContext db) => {
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
    // בדיקה אם המשתמש כבר קיים
    var existingUser = await db.Users.FirstOrDefaultAsync(u => u.Username == user.Username);
    if (existingUser != null)
        return Results.BadRequest("משתמש זה כבר קיים במערכת");

    db.Users.Add(user);
    await db.SaveChangesAsync();
    return Results.Ok(new { message = "User registered successfully" });
});

app.Run();
