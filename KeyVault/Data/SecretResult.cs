using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace KeyVault.Data {
	public class SecretResult {
		[JsonPropertyName("secretId")]
		public long SecretId { get; set; }
	}
}
