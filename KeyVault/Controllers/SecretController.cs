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

		[HttpGet("{secretName}/metadata")]
		public async ValueTask<OperationResult<SecretItem>> GetSecret([FromServices] IKeyVaultLogic keyVault, string secretName) {
			var result = await keyVault.GetSecret(HttpContext.User, secretName);
			SetStatusCode(result);
			return result;
		}

		[HttpPut("{secretName}/metadata")]
		public async ValueTask<OperationResult<SecretResult>> Update([FromServices] IKeyVaultLogic keyVault, string secretName, [FromBody] UpdateSecretDescription data) {
			var result = await keyVault.UpdateSecretDescription(HttpContext.User, secretName, data);
			SetStatusCode(result);
			return result;
		}



		[HttpGet("{secretName}/data")]
		public async ValueTask<OperationResult<AllSecretData>> GetData([FromServices] IKeyVaultLogic keyVault, string secretName) {
			var result = await keyVault.GetSecretDataForSecret(HttpContext.User, secretName);
			SetStatusCode(result);
			return result;
		}

		[HttpDelete("{secretName}/data")]
		public async ValueTask<OperationResult<CompletedResult>> DeleteDefaultSecretData([FromServices] IKeyVaultLogic keyVault, string secretName) {
			var result = await keyVault.DeleteSecretData(HttpContext.User, secretName, null);
			SetStatusCode(result);
			return result;
		}

		[HttpDelete("{secretName}/data/{name}")]
		public async ValueTask<OperationResult<CompletedResult>> DeleteSecretData([FromServices] IKeyVaultLogic keyVault, string secretName, string name) {
			var result = await keyVault.DeleteSecretData(HttpContext.User, secretName, name);
			SetStatusCode(result);
			return result;
		}

		[HttpPut("{secretName}/data")]
		public async ValueTask<OperationResult<CompletedResult>> UpdateDefaultSecretData([FromServices] IKeyVaultLogic keyVault, string secretName, [FromBody] UpdateSecretData data) {
			var result = await keyVault.UpdateSecretData(HttpContext.User, secretName, null, data);
			SetStatusCode(result);
			return result;
		}

		[HttpPut("{secretName}/data/{name}")]
		public async ValueTask<OperationResult<CompletedResult>> UpdateSecretData([FromServices] IKeyVaultLogic keyVault, string secretName, string name, [FromBody] UpdateSecretData data) {
			var result = await keyVault.UpdateSecretData(HttpContext.User, secretName, name, data);
			SetStatusCode(result);
			return result;
		}

		[HttpPost("{secretName}/data")]
		public async ValueTask<OperationResult<CompletedResult>> AddSecretData([FromServices] IKeyVaultLogic keyVault, string secretName, [FromBody] NewSecretData data) {
			var result = await keyVault.NewSecretData(HttpContext.User, secretName, data);
			SetStatusCode(result);
			return result;
		}

		[HttpGet("{secretName}/metadata/data")]
		public async ValueTask<OperationResult<SecretDataItem>> GetDefaultSecretDataDescription([FromServices] IKeyVaultLogic keyVault, string secretName) {
			var result = await keyVault.GetSecretData(HttpContext.User, secretName, null);
			SetStatusCode(result);
			return result;
		}

		[HttpGet("{secretName}/metadata/data/{name}")]
		public async ValueTask<OperationResult<SecretDataItem>> GetSecretDataDescription([FromServices] IKeyVaultLogic keyVault, string secretName, string name) {
			var result = await keyVault.GetSecretData(HttpContext.User, secretName, name);
			SetStatusCode(result);
			return result;
		}

		[HttpPut("{secretName}/metadata/data")]
		public async ValueTask<OperationResult<CompletedResult>> UpdateDefaultSecretDataDescription([FromServices] IKeyVaultLogic keyVault, string secretName, [FromBody] UpdateSecretDataDescription data) {
			var result = await keyVault.UpdateSecretDataDescription(HttpContext.User, secretName, null, data);
			SetStatusCode(result);
			return result;
		}

		[HttpPut("{secretName}/metadata/data/{name}")]
		public async ValueTask<OperationResult<CompletedResult>> UpdateSecretDataDescription([FromServices] IKeyVaultLogic keyVault, string secretName, string name, [FromBody] UpdateSecretDataDescription data) {
			var result = await keyVault.UpdateSecretDataDescription(HttpContext.User, secretName, name, data);
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

		[HttpPost("{secretName}/access")]
		public async ValueTask<OperationResult<CompletedResult>> AddAccess([FromServices] IKeyVaultLogic keyVault, string secretName, [FromBody] NewAccess data) {
			var result = await keyVault.AddSecretAccess(HttpContext.User, secretName, data.UserId, data);
			SetStatusCode(result);
			return result;
		}
	}
}
