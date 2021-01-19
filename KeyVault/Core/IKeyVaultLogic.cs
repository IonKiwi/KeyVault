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

		ValueTask<(bool success, string token)> AuthenticateBasic(string user, string password);
		ValueTask<(bool success, string token)> AuthenticateWindows(ClaimsPrincipal user);

		ValueTask<OperationResult<UserResult>> AddUser(ClaimsPrincipal user, NewUser newUser);
		ValueTask<OperationResult<UserData>> GetUser(ClaimsPrincipal user, long userId);
		ValueTask<OperationResult<CompletedResult>> UpdateUser(ClaimsPrincipal user, long userId, NewUser newUser);
		ValueTask<OperationResult<CompletedResult>> DeleteUser(ClaimsPrincipal user, long userId);
		ValueTask<OperationResult<AllUsersResult>> GetUsers(ClaimsPrincipal user);

		ValueTask<OperationResult<UserRolesResult>> GetUserRoles(ClaimsPrincipal user, long userId);
		ValueTask<OperationResult<UserRolesResult>> MergeUserRoles(ClaimsPrincipal user, long userId, string[] roles);
		ValueTask<OperationResult<UserRolesResult>> ReplaceUserRoles(ClaimsPrincipal user, long userId, string[] roles);
		ValueTask<OperationResult<UserRolesResult>> DeleteUserRoles(ClaimsPrincipal user, long userId, string[] roles);

		ValueTask<OperationResult<UserCredentialsResult>> GetCredentials(ClaimsPrincipal user, long userId);
		ValueTask<OperationResult<CompletedResult>> DeleteCredential(ClaimsPrincipal user, long userId, long credentialId);
		ValueTask<OperationResult<CredentialResult>> AddWindowsCredential(ClaimsPrincipal user, long userId, string account);
		ValueTask<OperationResult<CredentialResult>> AddBasicCredential(ClaimsPrincipal user, long userId, string username, string password);

		ValueTask<OperationResult<string>> GetSecretValue(ClaimsPrincipal user, string secretName, string name);
		ValueTask<OperationResult<(byte[] data, KeyVaultSecretType type)>> GetSecretValueAsBinrary(ClaimsPrincipal user, string secretName, string name);

		ValueTask<OperationResult<SecretItem>> GetSecret(ClaimsPrincipal user, string secretName);
		ValueTask<OperationResult<SecretResult>> NewSecret(ClaimsPrincipal user, NewSecret newSecret);
		ValueTask<OperationResult<SecretResult>> UpdateSecretDescription(ClaimsPrincipal user, string secretName, UpdateSecretDescription data);
		ValueTask<OperationResult<CompletedResult>> DeleteSecret(ClaimsPrincipal user, string secretName);
		ValueTask<OperationResult<AllSecretsResult>> GetAllSecrets(ClaimsPrincipal user);

		ValueTask<OperationResult<CompletedResult>> NewSecretData(ClaimsPrincipal user, string secretName, NewSecretData data);
		ValueTask<OperationResult<CompletedResult>> UpdateSecretDataDescription(ClaimsPrincipal user, string secretName, string name, UpdateSecretDataDescription data);
		ValueTask<OperationResult<CompletedResult>> UpdateSecretData(ClaimsPrincipal user, string secretName, string name, UpdateSecretData data);
		ValueTask<OperationResult<CompletedResult>> DeleteSecretData(ClaimsPrincipal user, string secretName, string name);
		ValueTask<OperationResult<SecretDataItem>> GetSecretData(ClaimsPrincipal user, string secretName, string name);
		ValueTask<OperationResult<AllSecretData>> GetSecretDataForSecret(ClaimsPrincipal user, string secretName);


		ValueTask<OperationResult<SecretAccessResult>> GetSecretAccess(ClaimsPrincipal user, string secretName);
		ValueTask<OperationResult<CompletedResult>> DeleteSecretAccess(ClaimsPrincipal user, string secretName, long userId);
		ValueTask<OperationResult<CompletedResult>> AddSecretAccess(ClaimsPrincipal user, string secretName, long userId, NewAccessData data);
		ValueTask<OperationResult<CompletedResult>> AddOrUpdateSecretAccess(ClaimsPrincipal user, string secretName, long userId, NewAccessData data);

		ValueTask<OperationResult<AllSecretsResult>> GetSecretsWithNoAccess(ClaimsPrincipal user);
		ValueTask<OperationResult<CompletedResult>> DeleteSecretsWithNoAccess(ClaimsPrincipal user);
	}
}
