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

		[HttpGet()]
		public ValueTask<OperationResult<AllUsersResult>> GetAll([FromServices] IKeyVaultLogic keyVault) {
			return keyVault.GetUsers(HttpContext.User);
		}

		[HttpGet("{userId:long}")]
		public ValueTask<OperationResult<UserData>> Get([FromServices] IKeyVaultLogic keyVault, long userId) {
			return keyVault.GetUser(HttpContext.User, userId);
		}

		[HttpPost]
		public async ValueTask<OperationResult<UserResult>> Create([FromServices] IKeyVaultLogic keyVault, [FromBody] NewUser data) {
			var result = await keyVault.AddUser(HttpContext.User, data);
			SetStatusCode(result);
			return result;
		}

		[HttpPut("{userId:long}")]
		public async ValueTask<OperationResult<CompletedResult>> Update([FromServices] IKeyVaultLogic keyVault, long userId, [FromBody] UpdateUser data) {
			var result = await keyVault.UpdateUser(HttpContext.User, userId, data);
			SetStatusCode(result);
			return result;
		}

		[HttpDelete("{userId:long}")]
		public async ValueTask<OperationResult<CompletedResult>> Delete([FromServices] IKeyVaultLogic keyVault, long userId) {
			var result = await keyVault.DeleteUser(HttpContext.User, userId);
			SetStatusCode(result);
			return result;
		}
	}
}
