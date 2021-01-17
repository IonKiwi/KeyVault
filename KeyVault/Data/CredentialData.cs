using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace KeyVault.Data {
	public class CredentialData {
		[JsonPropertyName("credentialId")]
		public long CredentialId { get; set; }
		[JsonPropertyName("credentialType")]
		public string CredentialType { get; set; }
		[JsonPropertyName("identifier")]
		public string Identifier { get; set; }
	}
}
