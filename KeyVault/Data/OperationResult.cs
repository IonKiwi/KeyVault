using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace KeyVault.Data {
	public struct OperationResult<T> {
		[JsonPropertyName("unauthorized")]
		public bool Unauthorized { get; set; }
		[JsonPropertyName("notFound")]
		public bool NotFound { get; set; }
		[JsonPropertyName("conflict")]
		public bool Conflict { get; set; }
		[JsonPropertyName("created")]
		public bool Created { get; set; }
		[JsonPropertyName("validationFailed")]
		public bool ValidationFailed { get; set; }
		[JsonPropertyName("validationMessage")]
		public string ValidationMessage { get; set; }
		[JsonPropertyName("result")]
		public T Result { get; set; }
	}
}
