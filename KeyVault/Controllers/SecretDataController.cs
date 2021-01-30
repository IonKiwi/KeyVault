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
	[Route("secret/data")]
	[Authorize]
	public class SecretDataController : KeyVaultControllerBase {

		private readonly ILogger<SecretDataController> _logger;

		public SecretDataController(ILogger<SecretDataController> logger) {
			_logger = logger;
		}

		[HttpGet("{secretName}")]
		public async ValueTask<OperationResult<AllSecretData>> GetData([FromServices] IKeyVaultLogic keyVault, string secretName) {
			var result = await keyVault.GetSecretDataForSecret(HttpContext.User, secretName);
			SetStatusCode(result);
			return result;
		}

		[HttpDelete("{secretName}")]
		public async ValueTask<OperationResult<CompletedResult>> DeleteDefaultSecretData([FromServices] IKeyVaultLogic keyVault, string secretName) {
			var result = await keyVault.DeleteSecretData(HttpContext.User, secretName, null);
			SetStatusCode(result);
			return result;
		}

		[HttpDelete("{secretName}/{name}")]
		public async ValueTask<OperationResult<CompletedResult>> DeleteSecretData([FromServices] IKeyVaultLogic keyVault, string secretName, string name) {
			var result = await keyVault.DeleteSecretData(HttpContext.User, secretName, name);
			SetStatusCode(result);
			return result;
		}

		[HttpPut("{secretName}")]
		public async ValueTask<OperationResult<CompletedResult>> UpdateDefaultSecretData([FromServices] IKeyVaultLogic keyVault, string secretName, [FromBody] UpdateSecretData data) {
			var result = await keyVault.UpdateSecretData(HttpContext.User, secretName, null, data);
			SetStatusCode(result);
			return result;
		}

		[HttpPut("{secretName}/{name}")]
		public async ValueTask<OperationResult<CompletedResult>> UpdateSecretData([FromServices] IKeyVaultLogic keyVault, string secretName, string name, [FromBody] UpdateSecretData data) {
			var result = await keyVault.UpdateSecretData(HttpContext.User, secretName, name, data);
			SetStatusCode(result);
			return result;
		}

		[HttpPost("{secretName}")]
		public async ValueTask<OperationResult<CompletedResult>> AddSecretData([FromServices] IKeyVaultLogic keyVault, string secretName, [FromBody] NewSecretData data) {
			var result = await keyVault.NewSecretData(HttpContext.User, secretName, data);
			SetStatusCode(result);
			return result;
		}
	}
}
