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
using Microsoft.OpenApi.Models;
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
using System.Text.Json.Serialization;
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

			var keyVault = new KeyVaultLogic();
			keyVault.Initialize(global.KeyVault);
			services.AddSingleton<IKeyVaultLogic>(keyVault);

			services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
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

			services.AddAuthorization((o) => {
				o.AddPolicy("Windows", p => {
					p.AddAuthenticationSchemes(NegotiateDefaults.AuthenticationScheme);
					p.RequireAuthenticatedUser();
				});
			});

			services.AddControllers().AddJsonOptions(opts => {
				opts.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
			});
			services.AddSwaggerGen(c => {
				c.SwaggerDoc("v1", new OpenApiInfo { Title = "KeyVault", Version = "v1" });
			});
		}

		public void Configure(IApplicationBuilder app, IWebHostEnvironment env) {
			if (env.IsDevelopment()) {
				app.UseDeveloperExceptionPage();
				app.UseSwagger();
				app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "KeyVault v1"));
			}

			app.UseRouting();

			app.UseAuthentication();
			app.UseAuthorization();

			app.UseEndpoints(endpoints => {
				endpoints.MapControllers();
			});
		}
	}
}
