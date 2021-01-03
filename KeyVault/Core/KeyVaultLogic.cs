using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace KeyVault.Core {
	public sealed class KeyVaultLogic {

		private readonly object _syncRoot = new object();
		private bool _initialized;
		private IKeyVaultDataProvider _data;

		private KeyVaultLogic() {

		}

		public static KeyVaultLogic Instance { get; } = new KeyVaultLogic();

		public void Initialize(IKeyVaultDataProvider data) {
			lock (_syncRoot) {
				if (_initialized) {
					throw new InvalidOperationException("Already initialized");
				}
				_initialized = true;
				_data = data;
			}
		}

		private void EnsureInitialized() {
			if (!_initialized) {
				throw new InvalidOperationException("KeyVaultLogic is not initialized");
			}
		}

		public void AddUser() {
			EnsureInitialized();


		}
	}
}
