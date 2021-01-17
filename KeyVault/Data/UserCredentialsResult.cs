using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace KeyVault.Data {
	public class UserCredentialsResult {
		[JsonPropertyName("credentials")]
		public List<(long credentialId, string credentialType, string identifier)> Credentials { get; set; }
	}
}
