using KeyVault.Core;
using KeyVault.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace KeyVault.Controllers {
	[ApiController]
	[Route("secret/descriptor")]
	[Authorize]
	public class SecretController : KeyVaultControllerBase {

		private readonly ILogger<SecretController> _logger;

		public SecretController(ILogger<SecretController> logger) {
			_logger = logger;
		}

		[HttpGet]
		public async ValueTask<OperationResult<AllSecretsResult>> GetAllSecrets([FromServices] IKeyVaultLogic keyVault) {
			var result = await keyVault.GetAllSecrets(HttpContext.User);
			SetStatusCode(result);
			return result;
		}

		[HttpPost]
		public async ValueTask<OperationResult<SecretResult>> Post([FromServices] IKeyVaultLogic keyVault, [FromBody] NewSecret newSecret) {
			var result = await keyVault.NewSecret(HttpContext.User, newSecret);
			SetStatusCode(result);
			return result;
		}

		[HttpDelete("{secretName}")]
		public async ValueTask<OperationResult<CompletedResult>> Delete([FromServices] IKeyVaultLogic keyVault, string secretName) {
			var result = await keyVault.DeleteSecret(HttpContext.User, secretName);
			SetStatusCode(result);
			return result;
		}
	}
}
