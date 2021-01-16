using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace KeyVault.Config {
	public class GlobalConfig : IFarmSettings {
		[JsonPropertyName("serverBindings")]
		public List<ServerBinding> ServerBindings {
			get;
			set;
		}

		[JsonPropertyName("keyVault")]
		public KeyVaultConfiguration KeyVault {
			get;
			set;
		}

		public void Init() {
			if (ServerBindings != null) {
				foreach (var sb in ServerBindings) {
					sb.Init();
				}
			}
			if (KeyVault != null) {
				KeyVault.Init();
			}
		}

		IReadOnlyList<IServerBinding> IFarmSettings.ServerBindings => ServerBindings;

		IKeyVaultConfiguration IFarmSettings.KeyVault => KeyVault;
	}
}
