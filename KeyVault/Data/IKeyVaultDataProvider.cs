using KeyVault.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace KeyVault.Data {
	public interface IKeyVaultDataProvider {
		ValueTask Create();

		ValueTask<long> AddUser(NewUser user);
		ValueTask<bool> UpdateUser(long userId, UpdateUser newUser);
		ValueTask<bool> DeleteUser(long userId);
		ValueTask<UserInformation> GetUserInformation(long userId);
		ValueTask<List<UserInformation>> GetUsers();

		ValueTask<(long usserId, string value)?> GetUserCredential(string type, string identifier);
		ValueTask<List<(long credentialId, string type, string identifier)>> GetUserCredentials(long userId);
		ValueTask<bool> DeleteCredential(long credentialId);
		ValueTask<long> AddCredential(long userId, string type, string identifier, string value);

		ValueTask ReplaceUserRoles(long userId, string[] roles);
		ValueTask AddUserRoles(long userId, string[] roles);
		ValueTask<bool?> RemoveUserRoles(long userId, string[] roles);

		ValueTask<long> CreateSecret(long userId, string name, string description);
		ValueTask<long> UpdateSecretDescription(long userId, string name, string description);
		ValueTask<bool> DeleteSecret(long userId, string name);

		ValueTask<bool> AddSecretData(long userId, long secretId, string name, string description, KeyVaultSecretType type, byte[] value, byte[] iv);
		ValueTask<bool> UpdateSecretDataDescription(long userId, long secretId, string name, string description);
		ValueTask<bool> UpdateSecretData(long userId, long secretId, string name, KeyVaultSecretType type, byte[] value, byte[] iv);
		ValueTask<bool> DeleteSecretData(long userId, long secretId, string name);
		ValueTask<List<(string name, string description, KeyVaultSecretType type, long creatorUserId, DateTime createdDate, long? lastUpdateUserId, DateTime? lastUpdateDate)>> GetSecretData(long secretId);
		ValueTask<(KeyVaultSecretType type, byte[] value, byte[] iv)?> GetSecretData(long secretId, string name);

		ValueTask<KeyVaultSecret> GetSecret(string name);
		ValueTask<List<(long secretId, string name, string description, long creatorUserId, DateTime createdDate, long? lastUpdateUserId, DateTime? lastUpdateDate)>> GetSecrets();
		ValueTask<List<(long secretId, string name, string description, long creatorUserId, DateTime createdDate, long? lastUpdateUserId, DateTime? lastUpdateDate)>> GetSecrets(long userId);

		ValueTask<bool> DeleteSecretsWithNoAccess();
		ValueTask<List<(long secretId, string name, string description, long creatorUserId, DateTime createdDate, long? lastUpdateUserId, DateTime? lastUpdateDate)>> GetSecretsWithNoAccess();

		ValueTask<bool> DeleteSecretAccess(long secretId, long userId);
		ValueTask<bool> AddSecretAccess(long secretId, long userId, bool read, bool write, bool assign);
		ValueTask<bool> AddOrUpdateSecretAccess(long secretId, long userId, bool read, bool write, bool assign);
	}
}
