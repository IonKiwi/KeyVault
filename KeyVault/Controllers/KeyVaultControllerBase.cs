using KeyVault.Data;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace KeyVault.Controllers {
	public class KeyVaultControllerBase : ControllerBase {

		protected void SetStatusCode<T>(OperationResult<T> result) {
			if (result.Status == OperationStatus.Conflict) {
				HttpContext.Response.StatusCode = 409;
			}
			else if (result.Status == OperationStatus.NotFound) {
				HttpContext.Response.StatusCode = 404;
			}
			else if (result.Status == OperationStatus.Unauthorized) {
				HttpContext.Response.StatusCode = 401;
			}
			else if (result.Status == OperationStatus.ValidationError) {
				HttpContext.Response.StatusCode = 400;
			}
			else if (result.Status == OperationStatus.Created) {
				HttpContext.Response.StatusCode = 201;
			}
		}

	}
}
