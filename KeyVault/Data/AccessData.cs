using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace KeyVault.Data {

	public class AccessData {
		[JsonPropertyName("read")]
		public bool Read { get; set; }

		[JsonPropertyName("write")]
		public bool Write { get; set; }

		[JsonPropertyName("assign")]
		public bool Assign { get; set; }
	}
}
