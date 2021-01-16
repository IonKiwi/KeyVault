using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace KeyVault.Data {
	public interface IKeyVaultDataProvider {
		ValueTask Create();
	}
}
