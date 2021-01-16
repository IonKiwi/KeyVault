using KeyVault.Config;
using KeyVault.Core;
using KeyVault.Data;
using KeyVault.Extensions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace KeyVault {
	public class Startup {

		private readonly IWebHostEnvironment _hostingEnvironment;

		public Startup(IConfiguration configuration, IWebHostEnvironment hostingEnvironment) {
			Configuration = configuration;
			_hostingEnvironment = hostingEnvironment;
		}

		public IConfiguration Configuration { get; }

		public void ConfigureServices(IServiceCollection services) {

			ThreadPool.SetMinThreads(200, 200);

			var appSettings = new FarmSettingsValues();
			Configuration.GetSection("FarmSettings").Bind(appSettings);

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
			services.AddSingleton<IFarmSettings>(global);

			KeyVaultLogic.Initialize(global.KeyVault);

			services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
				.AddJwtBearer(options => {
					options.TokenValidationParameters =
										new TokenValidationParameters {
											LifetimeValidator = (before, expires, token, parameters) => expires > DateTime.UtcNow,
											ValidateAudience = false,
											ValidateIssuer = false,
											ValidateActor = false,
											ValidateLifetime = true,
											IssuerSigningKey = KeyVaultLogic.Instance.GetSecurityKey()
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

			services.AddAuthorization((o) => {
				o.AddPolicy("Windows", p => {
					p.AddAuthenticationSchemes(NegotiateDefaults.AuthenticationScheme);
					p.RequireAuthenticatedUser();
				});
			});
		}

		public void Configure(IApplicationBuilder app, IWebHostEnvironment env) {
			if (env.IsDevelopment()) {
				app.UseDeveloperExceptionPage();
			}

			app.UseRouting();

			app.UseAuthentication();
			app.UseAuthorization();

			app.UseEndpoints(endpoints => {

				endpoints.MapGet("/auth/windows", async context => {
					var result = await KeyVaultLogic.Instance.AuthenticateWindows(context.User);
					if (!result.success) {
						context.Response.StatusCode = 403;
						return;
					}
					await context.Response.WriteAsync(result.token);
				}).RequireAuthorization("Windows");

				endpoints.MapGet("/auth/basic", async context => {

					string authorization = context.Request.Headers["Authorization"];
					if (authorization != null && authorization.StartsWith("Basic ", StringComparison.Ordinal)) {
						var credentials = Encoding.UTF8.GetString(Convert.FromBase64String(authorization.Substring(6)));
						int x = credentials.IndexOf(':');
						if (x > 0) {
							string user = credentials.Substring(0, x);
							string password = credentials.Substring(x + 1);
							var result = await KeyVaultLogic.Instance.AuthenticateBasic(user, password);
							if (result.success) {
								await context.Response.WriteAsync(result.token);
								return;
							}
						}
					}

					context.Response.StatusCode = 401;
					context.Response.Headers["WWW-Authenticate"] = "Basic realm=\"KeyVault basic authentication\", charset=\"UTF-8\"";
				});

				endpoints.MapPost("/users", async context => {
					var user = await JsonSerializer.DeserializeAsync<NewUser>(context.Request.Body);
					var result = await KeyVaultLogic.Instance.AddUser(context.User, user);
					await WriteOperationResponse(context, result);
				});

				endpoints.MapGet("/users/{userId:long}", async context => {
					var result = await KeyVaultLogic.Instance.GetUser(context.User, long.Parse((string)context.Request.RouteValues["userId"], NumberStyles.None, CultureInfo.InvariantCulture));
					await WriteOperationResponse(context, result);
				});

				endpoints.MapGet("/", async context => {
					await context.Response.WriteAsync($"Hello {context.User.Identity.Name}!");
				}).RequireAuthorization();
			});
		}

		private static async Task WriteOperationResponse<T>(HttpContext context, OperationResult<T> result) {
			if (result.Unauthorized) {
				context.Response.StatusCode = 401;
				await context.Response.WriteAsJsonAsync(new { status = "Unauthorized" });
				return;
			}
			else if (result.NotFound) {
				context.Response.StatusCode = 404;
				await context.Response.WriteAsJsonAsync(new { status = "NotFound" });
				return;
			}
			else if (result.ValidationFailed) {
				context.Response.StatusCode = 400;
				await context.Response.WriteAsJsonAsync(new { status = "ValidationFailed", validationMessage = result.ValidationMessage });
				return;
			}

			await context.Response.WriteAsJsonAsync(new { status = "Completed", result = result.Result });
		}
	}
}
