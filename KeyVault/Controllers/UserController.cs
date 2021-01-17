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
	public class UserController : ControllerBase {

		private readonly ILogger<UserController> _logger;

		public UserController(ILogger<UserController> logger) {
			_logger = logger;
		}

		[HttpGet("{userId:long}")]
		public ValueTask<OperationResult<UserData>> Get([FromServices] KeyVaultLogic keyVault, long userId) {
			return keyVault.GetUser(HttpContext.User, userId);
		}

		[HttpPost]
		public ValueTask<OperationResult<long>> Post([FromServices] KeyVaultLogic keyVault, [FromBody] NewUser newUser) {
			return keyVault.AddUser(HttpContext.User, newUser);
		}

		[HttpGet("{userId:long}/role")]
		public ValueTask<OperationResult<string[]>> Roles([FromServices] KeyVaultLogic keyVault, long userId) {
			return keyVault.GetUserRoles(HttpContext.User, userId);
		}

		[HttpPut("{userId:long}/role")]
		public ValueTask<OperationResult<string[]>> ReplaceRoles([FromServices] KeyVaultLogic keyVault, long userId, [FromBody] string[] roles) {
			return keyVault.ReplaceUserRoles(HttpContext.User, userId, roles);
		}

		[HttpPatch("{userId:long}/role")]
		public ValueTask<OperationResult<string[]>> MergeRoles([FromServices] KeyVaultLogic keyVault, long userId, [FromBody] string[] roles) {
			return keyVault.MergeUserRoles(HttpContext.User, userId, roles);
		}

		[HttpDelete("{userId:long}/role")]
		public ValueTask<OperationResult<string[]>> DeleteRoles([FromServices] KeyVaultLogic keyVault, long userId, [FromBody] string[] roles) {
			return keyVault.DeleteUserRoles(HttpContext.User, userId, roles);
		}
	}
}
