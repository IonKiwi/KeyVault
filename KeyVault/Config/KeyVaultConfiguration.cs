using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace KeyVault.Config {
	public interface IKeyVaultConfiguration {
		IKeyVaultEncryptionKey EncryptionKey { get; }
		IKeyVaultTokenKey TokenKey { get; }
		string DataProvider { get; }
		string DataProviderConnectionString { get; }
	}

	public sealed class KeyVaultConfiguration : IKeyVaultConfiguration {
		[JsonPropertyName("encryptionKey")]
		public KeyVaultEncryptionKey EncryptionKey { get; set; }

		[JsonPropertyName("tokenKey")]
		public KeyVaultTokenKey TokenKey { get; set; }

		[JsonPropertyName("dataProvider")]
		public string DataProvider { get; set; }

		[JsonPropertyName("dataProviderConnectionString")]
		public string DataProviderConnectionString { get; set; }

		public void Init() {
			if (EncryptionKey != null) {
				EncryptionKey.Init();
			}
		}

		IKeyVaultEncryptionKey IKeyVaultConfiguration.EncryptionKey => EncryptionKey;

		IKeyVaultTokenKey IKeyVaultConfiguration.TokenKey => TokenKey;
	}
}
