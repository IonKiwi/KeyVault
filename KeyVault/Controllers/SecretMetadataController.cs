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
	[Route("secret/metadata")]
	[Authorize]
	public class SecretMetadataController : KeyVaultControllerBase {

		private readonly ILogger<SecretMetadataController> _logger;

		public SecretMetadataController(ILogger<SecretMetadataController> logger) {
			_logger = logger;
		}

		[HttpGet("descriptor/{secretName}")]
		public async ValueTask<OperationResult<SecretItem>> GetSecret([FromServices] IKeyVaultLogic keyVault, string secretName) {
			var result = await keyVault.GetSecret(HttpContext.User, secretName);
			SetStatusCode(result);
			return result;
		}

		[HttpPut("descriptor/{secretName}")]
		public async ValueTask<OperationResult<SecretResult>> Update([FromServices] IKeyVaultLogic keyVault, string secretName, [FromBody] UpdateSecretDescription data) {
			var result = await keyVault.UpdateSecretDescription(HttpContext.User, secretName, data);
			SetStatusCode(result);
			return result;
		}



		[HttpGet("data/{secretName}")]
		public async ValueTask<OperationResult<SecretDataItem>> GetDefaultSecretDataDescription([FromServices] IKeyVaultLogic keyVault, string secretName) {
			var result = await keyVault.GetSecretData(HttpContext.User, secretName, null);
			SetStatusCode(result);
			return result;
		}

		[HttpGet("data/{secretName}/{name}")]
		public async ValueTask<OperationResult<SecretDataItem>> GetSecretDataDescription([FromServices] IKeyVaultLogic keyVault, string secretName, string name) {
			var result = await keyVault.GetSecretData(HttpContext.User, secretName, name);
			SetStatusCode(result);
			return result;
		}

		[HttpPut("data/{secretName}")]
		public async ValueTask<OperationResult<CompletedResult>> UpdateDefaultSecretDataDescription([FromServices] IKeyVaultLogic keyVault, string secretName, [FromBody] UpdateSecretDataDescription data) {
			var result = await keyVault.UpdateSecretDataDescription(HttpContext.User, secretName, null, data);
			SetStatusCode(result);
			return result;
		}

		[HttpPut("data/{secretName}/{name}")]
		public async ValueTask<OperationResult<CompletedResult>> UpdateSecretDataDescription([FromServices] IKeyVaultLogic keyVault, string secretName, string name, [FromBody] UpdateSecretDataDescription data) {
			var result = await keyVault.UpdateSecretDataDescription(HttpContext.User, secretName, name, data);
			SetStatusCode(result);
			return result;
		}
	}
}
