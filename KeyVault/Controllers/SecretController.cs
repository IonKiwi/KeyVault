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
	[Route("[controller]")]
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

		[HttpGet("{secretName}")]
		public async ValueTask<IActionResult> Get([FromServices] IKeyVaultLogic keyVault, string secretName) {
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
		public async ValueTask<OperationResult<SecretResult>> Post([FromServices] IKeyVaultLogic keyVault, [FromBody] NewSecret newSecret) {
			var result = await keyVault.NewSecret(HttpContext.User, newSecret);
			SetStatusCode(result);
			return result;
		}

		[HttpPut("{secretName}")]
		public async ValueTask<OperationResult<SecretResult>> Update([FromServices] IKeyVaultLogic keyVault, string secretName, [FromBody] NewSecretData data) {
			var result = await keyVault.UpdateSecret(HttpContext.User, secretName, data);
			SetStatusCode(result);
			return result;
		}

		[HttpDelete("{secretName}")]
		public async ValueTask<OperationResult<CompletedResult>> Delete([FromServices] IKeyVaultLogic keyVault, string secretName) {
			var result = await keyVault.DeleteSecret(HttpContext.User, secretName);
			SetStatusCode(result);
			return result;
		}

		[HttpGet("NoAccess")]
		public async ValueTask<OperationResult<AllSecretsResult>> NoAccess([FromServices] IKeyVaultLogic keyVault) {
			var result = await keyVault.GetSecretsWithNoAccess(HttpContext.User);
			SetStatusCode(result);
			return result;
		}

		[HttpDelete("NoAccess")]
		public async ValueTask<OperationResult<CompletedResult>> DeleteNoAccess([FromServices] IKeyVaultLogic keyVault) {
			var result = await keyVault.DeleteSecretsWithNoAccess(HttpContext.User);
			SetStatusCode(result);
			return result;
		}

		[HttpGet("{secretName}/access")]
		public async ValueTask<OperationResult<SecretAccessResult>> Access([FromServices] IKeyVaultLogic keyVault, string secretName) {
			var result = await keyVault.GetSecretAccess(HttpContext.User, secretName);
			SetStatusCode(result);
			return result;
		}

		[HttpDelete("{secretName}/access/{userId:long}")]
		public async ValueTask<OperationResult<CompletedResult>> DeleteAccess([FromServices] IKeyVaultLogic keyVault, string secretName, long userId) {
			var result = await keyVault.DeleteSecretAccess(HttpContext.User, secretName, userId);
			SetStatusCode(result);
			return result;
		}

		[HttpPut("{secretName}/access/{userId:long}")]
		public async ValueTask<OperationResult<CompletedResult>> AddOrUpdateSecretAccess([FromServices] IKeyVaultLogic keyVault, string secretName, long userId, [FromBody] NewAccessData data) {
			var result = await keyVault.AddOrUpdateSecretAccess(HttpContext.User, secretName, userId, data);
			SetStatusCode(result);
			return result;
		}

		[HttpPost("{secretName}/access/{userId:long}")]
		public async ValueTask<OperationResult<CompletedResult>> AddAccess([FromServices] IKeyVaultLogic keyVault, string secretName, long userId, [FromBody] NewAccessData data) {
			var result = await keyVault.AddSecretAccess(HttpContext.User, secretName, userId, data);
			SetStatusCode(result);
			return result;
		}
	}
}
