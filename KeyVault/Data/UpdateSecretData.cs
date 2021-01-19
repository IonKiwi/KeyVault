using KeyVault.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace KeyVault.Data {
	public class UpdateSecretData {

		[JsonPropertyName("value")]
		public string Value { get; set; }

		[JsonPropertyName("type")]
		public KeyVaultSecretType? SecretType { get; set; }
	}
}
