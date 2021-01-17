using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace KeyVault.Core {
	public sealed class KeyVaultSecret {
		public KeyVaultSecret(long id, string name, KeyVaultSecretType type, byte[] value, byte[] iv, DateTime created, long createdByUserId, DateTime? lastUpdate, long? lastUpdatedByUserId, IReadOnlyDictionary<long, KeyVaultSecretAccess> access) {
			Id = id;
			Name = name;
			SecretType = type;
			Value = value;
			IV = iv;
			Created = created;
			CreatedByUserId = createdByUserId;
			LastUpdate = lastUpdate;
			LastUpdatedByUserId = lastUpdatedByUserId;
			Access = access;
		}

		public long Id { get; }
		public string Name { get; }
		public KeyVaultSecretType SecretType { get; }
		public byte[] Value { get; }
		public byte[] IV { get; }
		public DateTime Created { get; }
		public long CreatedByUserId { get; }
		public DateTime? LastUpdate { get; }
		public long? LastUpdatedByUserId { get; }
		public IReadOnlyDictionary<long, KeyVaultSecretAccess> Access { get; }
	}

	public enum KeyVaultSecretType {
		Text,
		Blob
	}

	public sealed class KeyVaultSecretAccess {
		public KeyVaultSecretAccess(KeyVaultSecret parent, long userId, bool read, bool write, bool assign) {
			Parent = parent;
			UserId = userId;
			Read = read;
			Write = write;
			Assign = assign;
		}

		public KeyVaultSecret Parent { get; }
		public long UserId { get; }
		public bool Read { get; }
		public bool Write { get; }
		public bool Assign { get; }
	}
}
