using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace KeyVault.Config {
	public interface IKeyVaultConfiguration {
		byte[] EncryptionKey { get; }
		byte[] TokenKey { get; }
		string DataProvider { get; }
		string DataProviderConnectionString { get; }
	}

	public class KeyVaultConfiguration : IKeyVaultConfiguration {
		[JsonPropertyName("encryptionKey")]
		public byte[] EncryptionKey { get; set; }

		[JsonPropertyName("tokenKey")]
		public byte[] TokenKey { get; set; }

		[JsonPropertyName("dataProvider")]
		public string DataProvider { get; set; }

		[JsonPropertyName("dataProviderConnectionString")]
		public string DataProviderConnectionString { get; set; }

		public void Init() {
			
		}
	}
}
