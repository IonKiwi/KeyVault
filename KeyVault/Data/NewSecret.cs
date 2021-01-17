using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace KeyVault.Data {
	public class NewSecret : NewSecretData {

		[JsonPropertyName("name")]
		public string Name { get; set; }
	}

	public class NewSecretData {

		[JsonPropertyName("value")]
		public string Value { get; set; }

		[JsonPropertyName("type")]
		public string SecretType { get; set; }
	}
}
