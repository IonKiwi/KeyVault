using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace KeyVault.Core {
	public sealed class KeyVaultSecret {
		public KeyVaultSecret(long id, string name, string description, DateTime created, long createdByUserId, DateTime? lastUpdate, long? lastUpdatedByUserId, IReadOnlyDictionary<string, KeyVaultSecretData> data, IReadOnlyDictionary<long, KeyVaultSecretAccess> access) {
			Id = id;
			Name = name;
			Description = description;
			Created = created;
			CreatedByUserId = createdByUserId;
			LastUpdate = lastUpdate;
			LastUpdatedByUserId = lastUpdatedByUserId;
			Data = data;
			Access = access;
		}

		public long Id { get; }
		public string Name { get; }
		public string Description { get; }
		public DateTime Created { get; }
		public long CreatedByUserId { get; }
		public DateTime? LastUpdate { get; }
		public long? LastUpdatedByUserId { get; }
		public IReadOnlyDictionary<string, KeyVaultSecretData> Data { get; }
		public IReadOnlyDictionary<long, KeyVaultSecretAccess> Access { get; }
	}

	public enum KeyVaultSecretType {
		Text,
		Blob
	}

	public sealed class KeyVaultSecretAccess {
		public KeyVaultSecretAccess(KeyVaultSecret secret, long userId, bool read, bool write, bool assign) {
			Secret = secret;
			UserId = userId;
			Read = read;
			Write = write;
			Assign = assign;
		}

		public KeyVaultSecret Secret { get; }
		public long UserId { get; }
		public bool Read { get; }
		public bool Write { get; }
		public bool Assign { get; }
	}
}
