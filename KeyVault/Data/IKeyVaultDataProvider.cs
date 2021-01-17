using KeyVault.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace KeyVault.Data {
	public interface IKeyVaultDataProvider {
		ValueTask Create();
		ValueTask<UserInformation> GetUserInformation(long userId);
		ValueTask<List<UserInformation>> GetUsers();
		ValueTask<(long usserId, string value)?> GetUserCredential(string type, string identifier);
		ValueTask<List<(long credentialId, string type, string identifier)>> GetUserCredentials(long userId);
		ValueTask<bool> DeleteCredential(long credentialId);
		ValueTask<long> AddCredential(long userId, string type, string identifier, string value);
		ValueTask<long> AddUser(NewUser user);
		ValueTask<bool> UpdateUser(long userId, NewUser newUser);
		ValueTask<bool> DeleteUser(long userId);
		ValueTask ReplaceUserRoles(long userId, string[] roles);
		ValueTask AddUserRoles(long userId, string[] roles);
		ValueTask<bool?> RemoveUserRoles(long userId, string[] roles);
		ValueTask<long> CreateSecret(long userId, string name, KeyVaultSecretType type, byte[] value, byte[] iv);
		ValueTask<long> UpdateSecret(long userId, string name, KeyVaultSecretType type, byte[] value, byte[] iv);
		ValueTask<bool> DeleteSecret(long userId, string name);
		ValueTask<List<(long secretId, string name)>> GetSecrets();
		ValueTask<bool> DeleteSecretsWithNoAccess();
		ValueTask<List<(long secretId, string name)>> GetSecretsWithNoAccess();
		ValueTask<KeyVaultSecret> GetSecret(string name);
		ValueTask<bool> DeleteSecretAccess(long secretId, long userId);
		ValueTask<bool> AddOrUpdateSecretAccess(long secretId, long userId, bool read, bool write, bool assign);
	}
}
