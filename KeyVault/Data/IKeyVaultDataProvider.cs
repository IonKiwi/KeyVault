using KeyVault.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace KeyVault.Data {
	public interface IKeyVaultDataProvider {
		ValueTask Create();

		ValueTask<UserInformation> GetUserInformation(long userId);
		ValueTask<(long usserId, string value)?> GetUserCredential(string type, string identifier);
		ValueTask<long> AddUser(NewUser user);
		ValueTask ReplaceUserRoles(long userId, string[] roles);
		ValueTask AddUserRoles(long userId, string[] roles);
		ValueTask<bool?> RemoveUserRoles(long userId, string[] roles);
		ValueTask<long> CreateSecret(long userId, string name, byte[] value, byte[] iv);
		ValueTask<long> UpdateSecret(long userId, string name, byte[] value, byte[] iv);
		ValueTask<bool> DeleteSecret(long userId, string name);
		ValueTask<bool> DeleteSecretsWithNoAccess();
		ValueTask<List<(long secretId, string name)>> GetSecretsWithNoAccess();
		ValueTask<KeyVaultSecret> GetSecret(string name);
	}
}
