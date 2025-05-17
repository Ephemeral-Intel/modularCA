using Microsoft.EntityFrameworkCore;

using ModularCA.Database.Stores;
using ModularCA.Core.Interfaces;
using ModularCA.Core.Models;
using ModularCA.Database;
using ModularCA.Core.Implementations;
using FluentValidation;
using FluentValidation.AspNetCore;
using ModularCA.Core.Services;
using ModularCA.Core.Utils;
using ModularCA.Database.Services;
using ModularCA.API.Validation.SigningProfiles;
using ModularCA.API.Startup;
using ModularCA.Functions.Services;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using ModularCA.Shared.Models.SigningProfiles;
using ModularCA.API.Models;
using System.Linq;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

var configPath = Path.Combine(AppContext.BaseDirectory, "config", "db.yaml");
var dbConfig = YamlBootstrapLoader.Load(configPath);
var appConnStr = $"Server={dbConfig.App.Host};Port={dbConfig.App.Port};Database={dbConfig.App.Database};Uid={dbConfig.App.Username};Pwd={dbConfig.App.Password};";
builder.Services.AddDbContext<ModularCADbContext>(options =>
    options.UseMySql(
        appConnStr,
        ServerVersion.AutoDetect(appConnStr)
    ));

builder.Services.AddScoped<ISigningProfileService, EfSigningProfileService>();

builder.Services.AddScoped<ICertificateIssuanceService, CertificateIssuanceService>();

builder.Services.AddScoped<ICsrService, CsrService>();

// Configure dependency injection
var (signers, rawFullCAs, trustedCAs) = StartupKeystoreLoader.LoadAll(
    yamlPath: Path.Combine(AppContext.BaseDirectory, "config", "keystore.yaml"),
    keystorePath: Path.Combine(AppContext.BaseDirectory, "keystores")
);

var fullCAs = rawFullCAs
    .Select(x => new CertificateAuthorityIdentity(x.Cert, x.PrivateKey))
    .ToList();
var registry = new MultiCARegistry(fullCAs, trustedCAs);

var routeCAs = rawFullCAs
    .Select(x =>
    {
        var certDer = x.Cert.GetEncoded();
        if (certDer == null || certDer.Length == 0)
            throw new Exception("CA certificate is empty — parsing failed");

        var privKeyDer = PrivateKeyInfoFactory.CreatePrivateKeyInfo(x.PrivateKey).GetDerEncoded();

        var parsedCert = new X509CertificateParser().ReadCertificate(certDer);
        var parsedKey = PrivateKeyFactory.CreateKey(privKeyDer);
        return new BouncyCastleCertificateAuthority(certDer, privKeyDer);
    })
    .ToList();

// Pass that to a router
var router = new MultiCARouter(routeCAs, registry);

builder.Services.AddSingleton<MultiCARegistry>(registry);
builder.Services.AddSingleton<MultiCARouter>(router);
builder.Services.AddSingleton<IKeystoreCertificates>(registry);
builder.Services.AddSingleton<ICertificateAuthority>(router);


var Config = builder.Configuration.GetSection("CA");

builder.Services.AddScoped<ICsrService, CsrService>();

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddScoped<ICertificateStore, EfCertificateStore>();

builder.Services.AddSingleton<ITrustStoreProvider, InMemoryTrustStore>();

builder.Services.AddScoped<IFeatureFlagService, EfFeatureFlagService>();

builder.Services.AddScoped<ICertProfileService, EfCertProfileService>();

builder.Services.AddFluentValidationAutoValidation();
builder.Services.AddValidatorsFromAssemblyContaining<CreateSigningProfileValidator>();

builder.Services.AddScoped<ICsrParserService, CsrParserService>();

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", builder =>
    {
        builder.WithOrigins("http://localhost:3000") // or your dev URL
               .AllowAnyHeader()
               .AllowAnyMethod();
    });
});


var app = builder.Build();

//var trustStore = app.Services.GetRequiredService<ITrustStoreProvider>();
//trustStore.LoadFromFile("ca-trust.keystore"); // adjust path if needed


// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

//app.UseHttpsRedirection();

app.UseCors("AllowFrontend");

app.UseAuthorization();

app.MapControllers();

app.Run();
