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
	[Route("user/credential")]
	[Authorize]
	public class UserCredentialsController : KeyVaultControllerBase {

		private readonly ILogger<UserCredentialsController> _logger;

		public UserCredentialsController(ILogger<UserCredentialsController> logger) {
			_logger = logger;
		}

		[HttpGet("{userId:long}")]
		public async ValueTask<OperationResult<UserCredentialsResult>> Credentials([FromServices] IKeyVaultLogic keyVault, long userId) {
			var result = await keyVault.GetCredentials(HttpContext.User, userId);
			SetStatusCode(result);
			return result;
		}

		[HttpDelete("{userId:long}/{credentialId:long}")]
		public async ValueTask<OperationResult<CompletedResult>> Credentials([FromServices] IKeyVaultLogic keyVault, long userId, long credentialId) {
			var result = await keyVault.DeleteCredential(HttpContext.User, userId, credentialId);
			SetStatusCode(result);
			return result;
		}

		[HttpPut("{userId:long}/windows")]
		public async ValueTask<OperationResult<CredentialResult>> AddWindowsCredential([FromServices] IKeyVaultLogic keyVault, long userId, [FromBody] WindowsCredentialData data) {
			var result = await keyVault.AddWindowsCredential(HttpContext.User, userId, data.Account);
			SetStatusCode(result);
			return result;
		}

		[HttpPut("{userId:long}/basic")]
		public async ValueTask<OperationResult<CredentialResult>> AddBasicCredential([FromServices] IKeyVaultLogic keyVault, long userId, [FromBody] BasicCredentialData data) {
			var result = await keyVault.AddBasicCredential(HttpContext.User, userId, data.Username, data.Password);
			SetStatusCode(result);
			return result;
		}
	}
}
