using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace KeyVault.Data {
	public enum OperationStatus {
		Completed,
		Unauthorized,
		NotFound,
		Conflict,
		Created,
		ValidationError,
	}

	public struct OperationResult<T> {
		[JsonPropertyName("status")]
		public OperationStatus Status { get; set; }
		[JsonPropertyName("message")]
		[JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
		public string Message { get; set; }
		[JsonPropertyName("result")]
		public T Result { get; set; }
	}
}
