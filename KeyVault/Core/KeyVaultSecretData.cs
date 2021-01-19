using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace KeyVault.Core {
	public sealed class KeyVaultSecretData {
		public KeyVaultSecretData(KeyVaultSecret secret, string name, string description, KeyVaultSecretType type, DateTime created, long createdByUserId, DateTime? lastUpdate, long? lastUpdatedByUserId) {
			Secret = secret;
			Name = name;
			Description = description;
			SecretType = type;
			Created = created;
			CreatedByUserId = createdByUserId;
			LastUpdate = lastUpdate;
			LastUpdatedByUserId = lastUpdatedByUserId;
		}

		public KeyVaultSecret Secret { get; }
		public string Name { get; }
		public string Description { get; }
		public KeyVaultSecretType SecretType { get; }
		public DateTime Created { get; }
		public long CreatedByUserId { get; }
		public DateTime? LastUpdate { get; }
		public long? LastUpdatedByUserId { get; }
	}
}
