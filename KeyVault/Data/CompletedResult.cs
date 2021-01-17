using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace KeyVault.Data {
	public class CompletedResult {
		[JsonPropertyName("completed")]
		public bool Completed { get; set; }
	}
}
