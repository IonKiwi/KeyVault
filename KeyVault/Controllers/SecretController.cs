using KeyVault.Core;
using KeyVault.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace KeyVault.Controllers {
	[ApiController]
	[Route("[controller]")]
	[Authorize]
	public class SecretController : ControllerBase {

		private readonly ILogger<SecretController> _logger;

		public SecretController(ILogger<SecretController> logger) {
			_logger = logger;
		}

		[HttpGet("{userId:long}")]
		public async ValueTask<IActionResult> Get([FromServices] KeyVaultLogic keyVault, string name) {
			var secret = await keyVault.GetSecret(HttpContext.User, name);
			if (secret.NotFound) {
				return NotFound();
			}
			else if (secret.Unauthorized) {
				return Unauthorized();
			}
			return new ObjectResult(secret.Result);
		}
	}
}
