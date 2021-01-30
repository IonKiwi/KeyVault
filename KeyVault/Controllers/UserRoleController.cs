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
	[Route("user/role")]
	[Authorize]
	public class UserRoleController : KeyVaultControllerBase {

		private readonly ILogger<UserRoleController> _logger;

		public UserRoleController(ILogger<UserRoleController> logger) {
			_logger = logger;
		}

		[HttpGet("{userId:long}")]
		public async ValueTask<OperationResult<UserRolesResult>> Roles([FromServices] IKeyVaultLogic keyVault, long userId) {
			var result = await keyVault.GetUserRoles(HttpContext.User, userId);
			SetStatusCode(result);
			return result;
		}

		[HttpPut("{userId:long}")]
		public async ValueTask<OperationResult<UserRolesResult>> ReplaceRoles([FromServices] IKeyVaultLogic keyVault, long userId, [FromBody] string[] roles) {
			var result = await keyVault.ReplaceUserRoles(HttpContext.User, userId, roles);
			SetStatusCode(result);
			return result;
		}

		[HttpPatch("{userId:long}")]
		public async ValueTask<OperationResult<UserRolesResult>> MergeRoles([FromServices] IKeyVaultLogic keyVault, long userId, [FromBody] string[] roles) {
			var result = await keyVault.MergeUserRoles(HttpContext.User, userId, roles);
			SetStatusCode(result);
			return result;
		}

		[HttpDelete("{userId:long}")]
		public async ValueTask<OperationResult<UserRolesResult>> DeleteRoles([FromServices] IKeyVaultLogic keyVault, long userId, [FromBody] string[] roles) {
			var result = await keyVault.DeleteUserRoles(HttpContext.User, userId, roles);
			SetStatusCode(result);
			return result;
		}
	}
}
