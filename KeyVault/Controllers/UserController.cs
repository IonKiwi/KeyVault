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
		public ValueTask<OperationResult<UserData>> Get([FromServices] KeyVaultLogic keyVault, long userId) {
			return keyVault.GetUser(HttpContext.User, userId);
		}

		[HttpPost]
		public async ValueTask<OperationResult<long>> Create([FromServices] KeyVaultLogic keyVault, [FromBody] NewUser newUser) {
			var result = await keyVault.AddUser(HttpContext.User, newUser);
			SetStatusCode(result);
			return result;
		}

		[HttpPut("{userId:long}")]
		public async ValueTask<OperationResult<bool>> Update([FromServices] KeyVaultLogic keyVault, long userId, [FromBody] NewUser newUser) {
			var result = await keyVault.UpdateUser(HttpContext.User, userId, newUser);
			SetStatusCode(result);
			return result;
		}

		[HttpDelete("{userId:long}")]
		public async ValueTask<OperationResult<bool>> Delete([FromServices] KeyVaultLogic keyVault, long userId) {
			var result = await keyVault.DeleteUser(HttpContext.User, userId);
			SetStatusCode(result);
			return result;
		}

		[HttpGet("{userId:long}/role")]
		public async ValueTask<OperationResult<string[]>> Roles([FromServices] KeyVaultLogic keyVault, long userId) {
			var result = await keyVault.GetUserRoles(HttpContext.User, userId);
			SetStatusCode(result);
			return result;
		}

		[HttpPut("{userId:long}/role")]
		public async ValueTask<OperationResult<string[]>> ReplaceRoles([FromServices] KeyVaultLogic keyVault, long userId, [FromBody] string[] roles) {
			var result = await keyVault.ReplaceUserRoles(HttpContext.User, userId, roles);
			SetStatusCode(result);
			return result;
		}

		[HttpPatch("{userId:long}/role")]
		public async ValueTask<OperationResult<string[]>> MergeRoles([FromServices] KeyVaultLogic keyVault, long userId, [FromBody] string[] roles) {
			var result = await keyVault.MergeUserRoles(HttpContext.User, userId, roles);
			SetStatusCode(result);
			return result;
		}

		[HttpDelete("{userId:long}/role")]
		public async ValueTask<OperationResult<string[]>> DeleteRoles([FromServices] KeyVaultLogic keyVault, long userId, [FromBody] string[] roles) {
			var result = await keyVault.DeleteUserRoles(HttpContext.User, userId, roles);
			SetStatusCode(result);
			return result;
		}
	}
}
