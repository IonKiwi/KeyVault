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
	[Route("secret/maintenance")]
	[Authorize]
	public class SecretMaintenanceController : KeyVaultControllerBase {

		private readonly ILogger<SecretMaintenanceController> _logger;

		public SecretMaintenanceController(ILogger<SecretMaintenanceController> logger) {
			_logger = logger;
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
	}
}
