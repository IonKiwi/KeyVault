﻿using KeyVault.Core;
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
	[Authorize]
	public class SecretController : KeyVaultControllerBase {

		private readonly ILogger<SecretController> _logger;

		public SecretController(ILogger<SecretController> logger) {
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
		public async ValueTask<IActionResult> Get([FromServices] IKeyVaultLogic keyVault, string secretName) {
			var secret = await keyVault.GetSecret(HttpContext.User, secretName);
			if (secret.NotFound) {
				return NotFound();
			}
			else if (secret.Unauthorized) {
				return Unauthorized();
			}
			return new ObjectResult(secret.Result);
		}

		[HttpPost]
		public async ValueTask<OperationResult<long>> Post([FromServices] IKeyVaultLogic keyVault, [FromBody] NewSecret newSecret) {
			var result = await keyVault.NewSecret(HttpContext.User, newSecret);
			SetStatusCode(result);
			return result;
		}

		[HttpPut("{secretName}")]
		public async ValueTask<OperationResult<long>> Update([FromServices] IKeyVaultLogic keyVault, string secretName, [FromBody] NewSecretData data) {
			var result = await keyVault.UpdateSecret(HttpContext.User, secretName, data);
			SetStatusCode(result);
			return result;
		}

		[HttpDelete("{secretName}")]
		public async ValueTask<OperationResult<bool>> Delete([FromServices] IKeyVaultLogic keyVault, string secretName) {
			var result = await keyVault.DeleteSecret(HttpContext.User, secretName);
			SetStatusCode(result);
			return result;
		}

		[HttpGet("NoAccess")]
		public async ValueTask<OperationResult<List<(long secretId, string name)>>> NoAccess([FromServices] IKeyVaultLogic keyVault) {
			var result = await keyVault.GetSecretsWithNoAccess(HttpContext.User);
			SetStatusCode(result);
			return result;
		}

		[HttpDelete("NoAccess")]
		public async ValueTask<OperationResult<bool>> DeleteNoAccess([FromServices] IKeyVaultLogic keyVault) {
			var result = await keyVault.DeleteSecretsWithNoAccess(HttpContext.User);
			SetStatusCode(result);
			return result;
		}

		[HttpGet("{secretName}/access")]
		public async ValueTask<OperationResult<Dictionary<long, NewAccessData>>> Access([FromServices] IKeyVaultLogic keyVault, string secretName) {
			var result = await keyVault.GetSecretAccess(HttpContext.User, secretName);
			SetStatusCode(result);
			return result;
		}

		[HttpDelete("{secretName}/access/{userId:long}")]
		public async ValueTask<OperationResult<bool>> DeleteAccess([FromServices] IKeyVaultLogic keyVault, string secretName, long userId) {
			var result = await keyVault.DeleteSecretAccess(HttpContext.User, secretName, userId);
			SetStatusCode(result);
			return result;
		}

		[HttpPut("{secretName}/access/{userId:long}")]
		[HttpPost("{secretName}/access/{userId:long}")]
		public async ValueTask<OperationResult<bool>> AddAccess([FromServices] IKeyVaultLogic keyVault, string secretName, long userId, [FromBody] NewAccessData data) {
			var result = await keyVault.AddOrUpdateSecretAccess(HttpContext.User, secretName, userId, data);
			SetStatusCode(result);
			return result;
		}
	}
}