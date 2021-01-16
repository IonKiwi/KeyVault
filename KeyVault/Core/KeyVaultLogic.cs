using KeyVault.Config;
using KeyVault.Data;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace KeyVault.Core {
	public sealed class KeyVaultLogic {

		private readonly object _syncRoot = new object();
		private bool _initialized;
		private IKeyVaultDataProvider _data;
		private byte[] _tokenKey;
		private byte[] _encryptionKey;

		private KeyVaultLogic() {

		}

		public static KeyVaultLogic Instance { get; } = new KeyVaultLogic();

		public static void Initialize(IKeyVaultConfiguration configuration) {
			Instance.InitializeInternal(configuration);
		}

		private void InitializeInternal(IKeyVaultConfiguration configuration) {
			lock (_syncRoot) {
				if (_initialized) {
					throw new InvalidOperationException("Already initialized");
				}
				_initialized = true;
				_tokenKey = configuration.TokenKey;
				_encryptionKey = configuration.EncryptionKey;
				if (string.Equals("Sqlite", configuration.DataProvider, StringComparison.OrdinalIgnoreCase)) {
					_data = new SqliteKeyVaultDataProvider(configuration.DataProviderConnectionString);
				}
				else {
					throw new InvalidOperationException($"Data provider '{configuration.DataProvider}' is not supported");
				}
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

		public AsymmetricSecurityKey GetSecurityKey() {
			return new ECDsaSecurityKey(GetECDsa());
		}

		public JwtSecurityTokenHandler GetJwtTokenHandler() {
			return new JwtSecurityTokenHandler();
		}

		private ECDsa GetECDsa() {
			var ecdsa = ECDsa.Create();
			ecdsa.ImportPkcs8PrivateKey(_tokenKey, out _);
			return ecdsa;
		}

		private Aes GetAes() {
			var aes = Aes.Create();
			aes.Key = _encryptionKey;
			return aes;
		}
	}
}
