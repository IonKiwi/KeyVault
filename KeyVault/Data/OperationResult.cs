using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace KeyVault.Data {
	public struct OperationResult<T> {
		public bool Unauthorized { get; set; }
		public bool NotFound { get; set; }
		public bool Conflict { get; set; }
		public bool ValidationFailed { get; set; }
		public string ValidationMessage { get; set; }
		public T Result { get; set; }
	}
}
