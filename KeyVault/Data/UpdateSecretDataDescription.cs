using KeyVault.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace KeyVault.Data {
	public class UpdateSecretDataDescription {

		[JsonPropertyName("description")]
		public string Description { get; set; }
	}
}
