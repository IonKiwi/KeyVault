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
	[Route("secret/access")]
	[Authorize]
	public class SecretAccessController : KeyVaultControllerBase {

		private readonly ILogger<SecretAccessController> _logger;

		public SecretAccessController(ILogger<SecretAccessController> logger) {
			_logger = logger;
		}
		
		[HttpGet("{secretName}")]
		public async ValueTask<OperationResult<SecretAccessResult>> Access([FromServices] IKeyVaultLogic keyVault, string secretName) {
			var result = await keyVault.GetSecretAccess(HttpContext.User, secretName);
			SetStatusCode(result);
			return result;
		}

		[HttpDelete("{secretName}/{userId:long}")]
		public async ValueTask<OperationResult<CompletedResult>> DeleteAccess([FromServices] IKeyVaultLogic keyVault, string secretName, long userId) {
			var result = await keyVault.DeleteSecretAccess(HttpContext.User, secretName, userId);
			SetStatusCode(result);
			return result;
		}

		[HttpPut("{secretName}/{userId:long}")]
		public async ValueTask<OperationResult<CompletedResult>> AddOrUpdateSecretAccess([FromServices] IKeyVaultLogic keyVault, string secretName, long userId, [FromBody] AccessData data) {
			var result = await keyVault.AddOrUpdateSecretAccess(HttpContext.User, secretName, userId, data);
			SetStatusCode(result);
			return result;
		}

		[HttpPost("{secretName}")]
		public async ValueTask<OperationResult<CompletedResult>> AddAccess([FromServices] IKeyVaultLogic keyVault, string secretName, [FromBody] UserAccessData data) {
			var result = await keyVault.AddSecretAccess(HttpContext.User, secretName, data.UserId, data);
			SetStatusCode(result);
			return result;
		}
	}
}
