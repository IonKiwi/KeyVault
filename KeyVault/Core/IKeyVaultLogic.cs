using KeyVault.Config;
using KeyVault.Data;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;

namespace KeyVault.Core {
	public interface IKeyVaultLogic {
		ValueTask Create();
		ValueTask<OperationResult<UserResponse>> AddUser(ClaimsPrincipal user, NewUser newUser);
		ValueTask<(bool success, string token)> AuthenticateBasic(string user, string password);
		ValueTask<(bool success, string token)> AuthenticateWindows(ClaimsPrincipal user);
		ValueTask<OperationResult<CompletedResult>> DeleteSecret(ClaimsPrincipal user, string name);
		ValueTask<OperationResult<CompletedResult>> DeleteSecretsWithNoAccess(ClaimsPrincipal user);
		ValueTask<OperationResult<CompletedResult>> DeleteUser(ClaimsPrincipal user, long userId);
		ValueTask<OperationResult<RolesResult>> DeleteUserRoles(ClaimsPrincipal user, long userId, string[] roles);
		ValueTask<OperationResult<string>> GetSecret(ClaimsPrincipal user, string name);
		ValueTask<OperationResult<List<(long secretId, string name)>>> GetSecretsWithNoAccess(ClaimsPrincipal user);
		ValueTask<OperationResult<UserData>> GetUser(ClaimsPrincipal user, long userId);
		ValueTask<OperationResult<RolesResult>> GetUserRoles(ClaimsPrincipal user, long userId);
		ValueTask<OperationResult<RolesResult>> MergeUserRoles(ClaimsPrincipal user, long userId, string[] roles);
		ValueTask<OperationResult<SecretResult>> NewSecret(ClaimsPrincipal user, NewSecret newSecret);
		ValueTask<OperationResult<RolesResult>> ReplaceUserRoles(ClaimsPrincipal user, long userId, string[] roles);
		ValueTask<OperationResult<SecretResult>> UpdateSecret(ClaimsPrincipal user, string secretName, NewSecretData data);
		ValueTask<OperationResult<CompletedResult>> UpdateUser(ClaimsPrincipal user, long userId, NewUser newUser);
		ValueTask<OperationResult<List<(long credentialId, string credentialType, string identifier)>>> GetCredentials(ClaimsPrincipal user, long userId);
		ValueTask<OperationResult<CompletedResult>> DeleteCredential(ClaimsPrincipal user, long userId, long credentialId);
		ValueTask<OperationResult<CredentialResult>> AddWindowsCredential(ClaimsPrincipal user, long userId, string account);
		ValueTask<OperationResult<CredentialResult>> AddBasicCredential(ClaimsPrincipal user, long userId, string username, string password);
		ValueTask<OperationResult<Dictionary<long, NewAccessData>>> GetSecretAccess(ClaimsPrincipal user, string secretName);
		ValueTask<OperationResult<CompletedResult>> DeleteSecretAccess(ClaimsPrincipal user, string secretName, long userId);
		ValueTask<OperationResult<CompletedResult>> AddOrUpdateSecretAccess(ClaimsPrincipal user, string secretName, long userId, NewAccessData data);
	}
}
