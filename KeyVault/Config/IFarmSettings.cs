using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace KeyVault.Config {
	public interface IFarmSettings {
		IReadOnlyList<IServerBinding> ServerBindings { get; }
		IKeyVaultConfiguration KeyVault { get; }
	}
}
