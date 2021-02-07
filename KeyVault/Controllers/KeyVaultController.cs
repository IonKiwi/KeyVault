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

		[HttpGet("{secretName}")]
		[Authorize]
		public async ValueTask<IActionResult> GetDefault([FromServices] IKeyVaultLogic keyVault, string secretName, KeyVaultSecretValueMode mode) {
			if (mode == KeyVaultSecretValueMode.Text) {
				var secret = await keyVault.GetSecretValue(HttpContext.User, secretName, null);
				if (secret.Status == OperationStatus.NotFound) {
					return NotFound();
				}
				else if (secret.Status == OperationStatus.Unauthorized) {
					return Unauthorized();
				}
				return new ObjectResult(secret.Result);
			}
			else if (mode == KeyVaultSecretValueMode.Binary) {
				var secret = await keyVault.GetSecretValueAsBinrary(HttpContext.User, secretName, null);
				if (secret.Status == OperationStatus.NotFound) {
					return NotFound();
				}
				else if (secret.Status == OperationStatus.Unauthorized) {
					return Unauthorized();
				}
				if (secret.Result.type == KeyVaultSecretType.Text) {
					return File(secret.Result.data, "text/plain; charset=utf-8");
				}
				return File(secret.Result.data, "application/octet-stream");
			}
			else {
				throw new NotImplementedException(mode.ToString());
			}
		}

		[HttpGet("{secretName}/{name}")]
		[Authorize]
		public async ValueTask<IActionResult> Get([FromServices] IKeyVaultLogic keyVault, string secretName, string name, KeyVaultSecretValueMode mode) {
			if (mode == KeyVaultSecretValueMode.Text) {
				var secret = await keyVault.GetSecretValue(HttpContext.User, secretName, name);
				if (secret.Status == OperationStatus.NotFound) {
					return NotFound();
				}
				else if (secret.Status == OperationStatus.Unauthorized) {
					return Unauthorized();
				}
				return new ObjectResult(secret.Result);
			}
			else if (mode == KeyVaultSecretValueMode.Binary) {
				var secret = await keyVault.GetSecretValueAsBinrary(HttpContext.User, secretName, name);
				if (secret.Status == OperationStatus.NotFound) {
					return NotFound();
				}
				else if (secret.Status == OperationStatus.Unauthorized) {
					return Unauthorized();
				}
				if (secret.Result.type == KeyVaultSecretType.Text) {
					return File(secret.Result.data, "text/plain; charset=utf-8");
				}
				return File(secret.Result.data, "application/octet-stream");
			}
			else {
				throw new NotImplementedException(mode.ToString());
			}
		}
	}
}
