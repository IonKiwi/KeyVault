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
	public class UserController : KeyVaultControllerBase {

		private readonly ILogger<UserController> _logger;

		public UserController(ILogger<UserController> logger) {
			_logger = logger;
		}

		[HttpGet("{userId:long}")]
		public ValueTask<OperationResult<UserData>> Get([FromServices] IKeyVaultLogic keyVault, long userId) {
			return keyVault.GetUser(HttpContext.User, userId);
		}

		[HttpPost]
		public async ValueTask<OperationResult<long>> Create([FromServices] IKeyVaultLogic keyVault, [FromBody] NewUser newUser) {
			var result = await keyVault.AddUser(HttpContext.User, newUser);
			SetStatusCode(result);
			return result;
		}

		[HttpPut("{userId:long}")]
		public async ValueTask<OperationResult<bool>> Update([FromServices] IKeyVaultLogic keyVault, long userId, [FromBody] NewUser newUser) {
			var result = await keyVault.UpdateUser(HttpContext.User, userId, newUser);
			SetStatusCode(result);
			return result;
		}

		[HttpDelete("{userId:long}")]
		public async ValueTask<OperationResult<bool>> Delete([FromServices] IKeyVaultLogic keyVault, long userId) {
			var result = await keyVault.DeleteUser(HttpContext.User, userId);
			SetStatusCode(result);
			return result;
		}

		[HttpGet("{userId:long}/credential")]
		public async ValueTask<OperationResult<List<(long credentialId, string credentialType, string identifier)>>> Credentials([FromServices] IKeyVaultLogic keyVault, long userId) {
			var result = await keyVault.GetCredentials(HttpContext.User, userId);
			SetStatusCode(result);
			return result;
		}

		[HttpDelete("{userId:long}/credential/{credentialId:long}")]
		public async ValueTask<OperationResult<bool>> Credentials([FromServices] IKeyVaultLogic keyVault, long userId, long credentialId) {
			var result = await keyVault.DeleteCredential(HttpContext.User, userId, credentialId);
			SetStatusCode(result);
			return result;
		}

		[HttpPut("{userId:long}/credential/windows")]
		public async ValueTask<OperationResult<long>> AddWindowsCredential([FromServices] IKeyVaultLogic keyVault, long userId, [FromBody] WindowsCredentialData data) {
			var result = await keyVault.AddWindowsCredential(HttpContext.User, userId, data.Account);
			SetStatusCode(result);
			return result;
		}

		[HttpPut("{userId:long}/credential/basic")]
		public async ValueTask<OperationResult<long>> AddBasicCredential([FromServices] IKeyVaultLogic keyVault, long userId, [FromBody] BasicCredentialData data) {
			var result = await keyVault.AddBasicCredential(HttpContext.User, userId, data.Username, data.Password);
			SetStatusCode(result);
			return result;
		}

		[HttpGet("{userId:long}/role")]
		public async ValueTask<OperationResult<string[]>> Roles([FromServices] IKeyVaultLogic keyVault, long userId) {
			var result = await keyVault.GetUserRoles(HttpContext.User, userId);
			SetStatusCode(result);
			return result;
		}

		[HttpPut("{userId:long}/role")]
		public async ValueTask<OperationResult<string[]>> ReplaceRoles([FromServices] IKeyVaultLogic keyVault, long userId, [FromBody] string[] roles) {
			var result = await keyVault.ReplaceUserRoles(HttpContext.User, userId, roles);
			SetStatusCode(result);
			return result;
		}

		[HttpPatch("{userId:long}/role")]
		public async ValueTask<OperationResult<string[]>> MergeRoles([FromServices] IKeyVaultLogic keyVault, long userId, [FromBody] string[] roles) {
			var result = await keyVault.MergeUserRoles(HttpContext.User, userId, roles);
			SetStatusCode(result);
			return result;
		}

		[HttpDelete("{userId:long}/role")]
		public async ValueTask<OperationResult<string[]>> DeleteRoles([FromServices] IKeyVaultLogic keyVault, long userId, [FromBody] string[] roles) {
			var result = await keyVault.DeleteUserRoles(HttpContext.User, userId, roles);
			SetStatusCode(result);
			return result;
		}
	}
}
