using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace KeyVault {
	public class Startup {

		//private readonly AsymmetricSecurityKey SecurityKey = new ECDsaSecurityKey(ECDsa.Create(ECCurve.NamedCurves.nistP384));
		private readonly AsymmetricSecurityKey SecurityKey = new ECDsaSecurityKey(GetECDsa());
		private readonly JwtSecurityTokenHandler JwtTokenHandler = new JwtSecurityTokenHandler();

		private static ECDsa GetECDsa() {
			var ecdsa = ECDsa.Create();
			ecdsa.ImportPkcs8PrivateKey(Convert.FromBase64String("MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDBMrfRKMqdHA36DrOIZZXEojQciBY0CJieGTVmGsycvZbpPb07fO53E8jd901Q091WhZANiAAQqTQ7w2DQtlbjYqLoipAm+tmriyjaPbUv/khNwaDCLhsx7QJGUt+UrYlP6l3ovExLaxwG+s7RLkHwAYg++fueMSgR9NpIGNrTobm4ESDz7kS9GDIXXcaxT90GmRUnv00M="), out _);
			return ecdsa;
		}

		public void ConfigureServices(IServiceCollection services) {

			services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
				.AddJwtBearer(options => {
					options.TokenValidationParameters =
										new TokenValidationParameters {
											LifetimeValidator = (before, expires, token, parameters) => expires > DateTime.UtcNow,
											ValidateAudience = false,
											ValidateIssuer = false,
											ValidateActor = false,
											ValidateLifetime = true,
											IssuerSigningKey = SecurityKey
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

				endpoints.MapGet("/auth", async context => {

					var claims = new[] { new Claim(ClaimTypes.Name, context.User.Identity.Name) };
					var credentials = new SigningCredentials(SecurityKey, SecurityAlgorithms.EcdsaSha256);
					var token = new JwtSecurityToken("KeyVault", "urn:target", claims, expires: DateTime.UtcNow.AddHours(2), signingCredentials: credentials);
					await context.Response.WriteAsync(JwtTokenHandler.WriteToken(token));

				}).RequireAuthorization("Windows");

				endpoints.MapGet("/", async context => {
					await context.Response.WriteAsync($"Hello {context.User.Identity.Name}!");
				}).RequireAuthorization();
			});
		}
	}
}
