using KeyVault.Data;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace KeyVault.Controllers {
	public class KeyVaultControllerBase : ControllerBase {

		protected void SetStatusCode<T>(OperationResult<T> result) {
			if (result.Conflict) {
				HttpContext.Response.StatusCode = 409;
			}
			else if (result.NotFound) {
				HttpContext.Response.StatusCode = 404;
			}
			else if (result.Unauthorized) {
				HttpContext.Response.StatusCode = 401;
			}
			else if (result.ValidationFailed) {
				HttpContext.Response.StatusCode = 400;
			}
			else if (result.Created) {
				HttpContext.Response.StatusCode = 201;
			}
		}

	}
}
