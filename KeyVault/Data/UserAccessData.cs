using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace KeyVault.Data {
	public class UserAccessData : AccessData {
		[JsonPropertyName("userId")]
		public long UserId { get; set; }
	}
}
