using KeyVault.Config;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using System.IO;
using System.Text.Json;
using System.Text;
using System.Threading;
using Microsoft.Extensions.DependencyInjection;
using KeyVault.Core;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication.Negotiate;
using System;
using Microsoft.Extensions.Hosting;
using KeyVault.PlatformSpecific;
using KeyVault.Utilities;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Hosting;
using System.Security.Authentication;

namespace KeyVault {
	public class Program {
		public static void Main(string[] args) {

			ThreadPool.SetMinThreads(200, 200);

			var builder = WebApplication.CreateBuilder(args);

			var appSettings = new FarmSettingsValues();
			builder.Configuration.GetSection("FarmSettings").Bind(appSettings);

			string json;
			using (var file = File.Open(appSettings.ConfigPath + Path.DirectorySeparatorChar + "KeyVault.json", FileMode.Open, FileAccess.Read, FileShare.ReadWrite)) {
				using (var sr = new StreamReader(file, Encoding.UTF8, false)) {
					json = sr.ReadToEnd();
				}
			}

			var global = JsonSerializer.Deserialize<GlobalConfig>(json, new JsonSerializerOptions() {
				PropertyNameCaseInsensitive = false,
				AllowTrailingCommas = false,
				ReadCommentHandling = JsonCommentHandling.Skip
			});

			global.Init();
			builder.Services.AddSingleton<IFarmSettings>(global);

			var keyVault = new KeyVaultLogic();
			keyVault.Initialize(global.KeyVault);
			builder.Services.AddSingleton<IKeyVaultLogic>(keyVault);

			builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
				.AddJwtBearer(options => {
					options.TokenValidationParameters =
										new TokenValidationParameters {
											LifetimeValidator = (before, expires, token, parameters) => expires > DateTime.UtcNow,
											ValidateAudience = false,
											ValidateIssuer = false,
											ValidateActor = false,
											ValidateLifetime = true,
											IssuerSigningKey = keyVault.GetSecurityKey()
										};

					//options.Events = new JwtBearerEvents {
					//	OnMessageReceived = context => {
					//		var accessToken = context.Request.Query["access_token"];
					//		if (!string.IsNullOrEmpty(accessToken)) {
					//			context.Token = context.Request.Query["access_token"];
					//		}
					//		return Task.CompletedTask;
					//	}
					//};
				})
				.AddNegotiate();

			builder.Services.AddAuthorization((o) => {
				o.AddPolicy("Windows", p => {
					p.AddAuthenticationSchemes(NegotiateDefaults.AuthenticationScheme);
					p.RequireAuthenticatedUser();
				});
			});

			builder.Services.AddControllers().AddJsonOptions(opts => {
				opts.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
			});
			builder.Services.AddSwaggerGen(c => {
				c.SwaggerDoc("v1", new OpenApiInfo { Title = "KeyVault", Version = "v1" });
			});

			builder.Services.Configure<KestrelServerOptions>(options => {
				var farmSettings = options.ApplicationServices.GetService<IFarmSettings>();
				var serverBindings = farmSettings.ServerBindings;
				if (serverBindings != null) {
					foreach (var kv in serverBindings) {
						var certificate = GetServerCertificate(kv.Config);
						if (certificate == null) {
							// http binding
							options.ListenAnyIP(kv.Port, listenOptions => {
								listenOptions.Protocols = HttpProtocols.Http1;
							});
						}
						else {
							// https binding
							var logger = options.ApplicationServices.GetService<ILoggerFactory>().CreateLogger<Program>();
							logger.LogInformation("Using TLS certificate " + certificate.Subject);
							CommonUtility.Verify(certificate, logger);

							var isWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
							options.ListenAnyIP(kv.Port, listenOptions => {
								listenOptions.Protocols = HttpProtocols.Http1AndHttp2;
								listenOptions.UseHttps(certificate, options => {
									if (isWindows) {
										options.SslProtocols = SslProtocols.Tls12;
									}
									else {
										options.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
									}
									//options.OnAuthenticate = (context, sslOptions) => {
									//	sslOptions.CipherSuitesPolicy = new CipherSuitesPolicy(new[] {
									//		TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
									//		TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
									//		TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
									//		TlsCipherSuite.TLS_AES_128_GCM_SHA256,
									//		TlsCipherSuite.TLS_AES_256_GCM_SHA384,
									//		TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
									//	});
									//};
								});
							});
						}
					}
				}
			});

			var app = builder.Build();

			if (app.Environment.IsDevelopment()) {
				app.UseDeveloperExceptionPage();
				app.UseSwagger();
				app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "KeyVault v1"));
			}

			app.UseRouting();

			app.UseAuthentication();
			app.UseAuthorization();

			app.MapControllers();

			app.Run();
		}

		private static X509Certificate2 GetServerCertificate(IServerCertificateSettings serverCertificateSettings) {
			if (serverCertificateSettings == null || string.IsNullOrEmpty(serverCertificateSettings.ServerCertificateProvider)) {
				return null;
			}

			if (!CommonUtility.TryParseEnum<ServerCertificateProviderType>(serverCertificateSettings.ServerCertificateProvider, true, out var serverCertificateProvider)) {
				throw new ApplicationException($"Unsupported ServerCertificateProvider in config: {serverCertificateSettings.ServerCertificateProvider}");
			}

			var serverCertificatePasswordProvider = ServerCertificatePasswordProviderType.None;
			if (!string.IsNullOrEmpty(serverCertificateSettings.ServerCertificatePasswordProvider) && !CommonUtility.TryParseEnum(serverCertificateSettings.ServerCertificatePasswordProvider, true, out serverCertificatePasswordProvider)) {
				throw new ApplicationException($"Unsupported ServerCertificatePasswordProvider in config: {serverCertificateSettings.ServerCertificatePasswordProvider}");
			}

			string password = null;
			if (serverCertificatePasswordProvider == ServerCertificatePasswordProviderType.Plain) {
				password = serverCertificateSettings.ServerCertificatePassword;
			}

			X509Certificate2 certificate = null;
			if (serverCertificateProvider == ServerCertificateProviderType.Blob) {
				byte[] certificateData = Convert.FromBase64String(serverCertificateSettings.ServerCertificate);
				certificate = new X509Certificate2(certificateData, password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.EphemeralKeySet);
			}
			else if (serverCertificateProvider == ServerCertificateProviderType.File) {
				certificate = new X509Certificate2(serverCertificateSettings.ServerCertificate, password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.EphemeralKeySet);
			}
			else if (serverCertificateProvider == ServerCertificateProviderType.WindowsStore && RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) {
				certificate = WindowsCertificateHelper.GetCertificate(StoreName.My, StoreLocation.LocalMachine, serverCertificateSettings.ServerCertificate, DateTime.UtcNow, true, false, out var status);
				if (certificate == null || status != CertificateRetrievalStatus.None) {
					throw new Exception("Certificate '" + serverCertificateSettings.ServerCertificate + "' not found/valid. status: " + status.ToString());
				}
			}
			return certificate;
		}

		internal enum ServerCertificateProviderType {
			Blob,
			File,
			WindowsStore,
		}

		internal enum ServerCertificatePasswordProviderType {
			None,
			Plain,
		}
	}
}
