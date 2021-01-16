using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace KeyVault.Config {
	public interface IKeyVaultEncryptionKey {
		byte[] Key { get; }
	}

	public sealed class KeyVaultEncryptionKey : IKeyVaultEncryptionKey {
		[JsonPropertyName("key")]
		public byte[] Key { get; set; }

		public void Init() {

		}
	}
}
