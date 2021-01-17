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
	public class KeyVaultController : KeyVaultControllerBase {

		private readonly ILogger<KeyVaultController> _logger;

		public KeyVaultController(ILogger<KeyVaultController> logger) {
			_logger = logger;
		}

		[HttpGet("create")]
		[AllowAnonymous]
		public async ValueTask<IActionResult> Create([FromServices] IWebHostEnvironment environment, [FromServices] IKeyVaultLogic keyVault) {
			if (!environment.IsDevelopment()) {
				throw new InvalidOperationException();
			}
			await keyVault.Create();
			return Ok();
		}
	}
}
