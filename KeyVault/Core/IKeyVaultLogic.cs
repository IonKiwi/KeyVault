using KeyVault.Config;
using KeyVault.Data;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;

namespace KeyVault.Core {
	public interface IKeyVaultLogic {
		ValueTask<OperationResult<long>> AddUser(ClaimsPrincipal user, NewUser newUser);
		ValueTask<(bool success, string token)> AuthenticateBasic(string user, string password);
		ValueTask<(bool success, string token)> AuthenticateWindows(ClaimsPrincipal user);
		ValueTask<OperationResult<bool>> DeleteSecret(ClaimsPrincipal user, string name);
		ValueTask<OperationResult<bool>> DeleteSecretsWithNoAccess(ClaimsPrincipal user);
		ValueTask<OperationResult<bool>> DeleteUser(ClaimsPrincipal user, long userId);
		ValueTask<OperationResult<string[]>> DeleteUserRoles(ClaimsPrincipal user, long userId, string[] roles);
		ValueTask<OperationResult<string>> GetSecret(ClaimsPrincipal user, string name);
		ValueTask<OperationResult<List<(long secretId, string name)>>> GetSecretsWithNoAccess(ClaimsPrincipal user);
		ValueTask<OperationResult<UserData>> GetUser(ClaimsPrincipal user, long userId);
		ValueTask<OperationResult<string[]>> GetUserRoles(ClaimsPrincipal user, long userId);
		ValueTask<OperationResult<string[]>> MergeUserRoles(ClaimsPrincipal user, long userId, string[] roles);
		ValueTask<OperationResult<long>> NewSecret(ClaimsPrincipal user, NewSecret newSecret);
		ValueTask<OperationResult<string[]>> ReplaceUserRoles(ClaimsPrincipal user, long userId, string[] roles);
		ValueTask<OperationResult<long>> UpdateSecret(ClaimsPrincipal user, string secretName, NewSecretData data);
		ValueTask<OperationResult<bool>> UpdateUser(ClaimsPrincipal user, long userId, NewUser newUser);
		ValueTask<OperationResult<List<(long credentialId, string credentialType, string identifier)>>> GetCredentials(ClaimsPrincipal user, long userId);
		ValueTask<OperationResult<bool>> DeleteCredential(ClaimsPrincipal user, long userId, long credentialId);
		ValueTask<OperationResult<long>> AddWindowsCredential(ClaimsPrincipal user, long userId, string account);
		ValueTask<OperationResult<long>> AddBasicCredential(ClaimsPrincipal user, long userId, string username, string password);
	}
}
