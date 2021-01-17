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

		[HttpGet("{secretName}")]
		public async ValueTask<IActionResult> Get([FromServices] KeyVaultLogic keyVault, string secretName) {
			var secret = await keyVault.GetSecret(HttpContext.User, secretName);
			if (secret.NotFound) {
				return NotFound();
			}
			else if (secret.Unauthorized) {
				return Unauthorized();
			}
			return new ObjectResult(secret.Result);
		}

		[HttpPost]
		public ValueTask<OperationResult<long>> Post([FromServices] KeyVaultLogic keyVault, [FromBody] NewSecret newSecret) {
			return keyVault.NewSecret(HttpContext.User, newSecret);
		}

		[HttpPut("{secretName}")]
		public ValueTask<OperationResult<long>> Update([FromServices] KeyVaultLogic keyVault, string secretName, [FromBody] NewSecretData data) {
			return keyVault.UpdateSecret(HttpContext.User, secretName, data);
		}

		[HttpDelete("{secretName}")]
		public ValueTask<OperationResult<bool>> Delete([FromServices] KeyVaultLogic keyVault, string secretName) {
			return keyVault.DeleteSecret(HttpContext.User, secretName);
		}

		[HttpGet("NoAccess")]
		public ValueTask<OperationResult<List<(long secretId, string name)>>> NoAccess([FromServices] KeyVaultLogic keyVault) {
			return keyVault.GetSecretsWithNoAccess(HttpContext.User);
		}

		[HttpDelete("NoAccess")]
		public ValueTask<OperationResult<bool>> DeleteNoAccess([FromServices] KeyVaultLogic keyVault) {
			return keyVault.DeleteSecretsWithNoAccess(HttpContext.User);
		}
	}
}
