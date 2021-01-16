using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace KeyVault.Config {
	public interface IKeyVaultTokenKey {
		byte[] Key { get; }
	}

	public sealed class KeyVaultTokenKey : IKeyVaultTokenKey {
		[JsonPropertyName("key")]
		public byte[] Key { get; set; }

		public void Init() {

		}
	}
}
