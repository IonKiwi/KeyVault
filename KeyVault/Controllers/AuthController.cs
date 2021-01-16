using KeyVault.Core;
using KeyVault.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KeyVault.Controllers {
	[ApiController]
	[Route("[controller]/[action]")]
	public class AuthController : ControllerBase {

		private readonly ILogger<AuthController> _logger;

		public AuthController(ILogger<AuthController> logger) {
			_logger = logger;
		}

		[HttpGet]
		[Authorize("Windows")]
		public async ValueTask<IActionResult> Windows() {
			var result = await KeyVaultLogic.Instance.AuthenticateWindows(HttpContext.User);
			if (!result.success) {
				return Unauthorized();
			}
			return new ObjectResult(result.token);
		}

		[HttpGet]
		public async ValueTask<IActionResult> Basic() {
			string authorization = HttpContext.Request.Headers["Authorization"];
			if (authorization != null && authorization.StartsWith("Basic ", StringComparison.Ordinal)) {
				var credentials = Encoding.UTF8.GetString(Convert.FromBase64String(authorization.Substring(6)));
				int x = credentials.IndexOf(':');
				if (x > 0) {
					string user = credentials.Substring(0, x);
					string password = credentials.Substring(x + 1);
					var result = await KeyVaultLogic.Instance.AuthenticateBasic(user, password);
					if (result.success) {
						return new ObjectResult(result.token);
					}
				}
			}

			HttpContext.Response.Headers["WWW-Authenticate"] = "Basic realm=\"KeyVault basic authentication\", charset=\"UTF-8\"";
			return StatusCode(401);
		}
	}
}
