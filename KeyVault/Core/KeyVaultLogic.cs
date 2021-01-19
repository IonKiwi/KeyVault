using KeyVault.Config;
using KeyVault.Data;
using KeyVault.Extensions;
using KeyVault.Utilities;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace KeyVault.Core {

	public sealed class KeyVaultLogic : IKeyVaultLogic {

		private IKeyVaultDataProvider _data;
		private IKeyVaultTokenKey _tokenKey;
		private IKeyVaultEncryptionKey _encryptionKey;

		public void Initialize(IKeyVaultConfiguration configuration) {
			_tokenKey = configuration.TokenKey;
			_encryptionKey = configuration.EncryptionKey;
			if (string.Equals("Sqlite", configuration.DataProvider, StringComparison.OrdinalIgnoreCase)) {
				_data = new SqliteKeyVaultDataProvider(configuration.DataProviderConnectionString);
			}
			else {
				throw new InvalidOperationException($"Data provider '{configuration.DataProvider}' is not supported");
			}
		}

		public ValueTask Create() {
			return _data.Create();
		}

		public AsymmetricSecurityKey GetSecurityKey() {
			return new ECDsaSecurityKey(GetECDsa());
		}

		public JwtSecurityTokenHandler GetJwtTokenHandler() {
			return new JwtSecurityTokenHandler();
		}

		private ECDsa GetECDsa() {
			var ecdsa = ECDsa.Create();
			ecdsa.ImportPkcs8PrivateKey(_tokenKey.Key, out _);
			return ecdsa;
		}

		private Aes GetAes() {
			var aes = Aes.Create();
			aes.Key = _encryptionKey.Key;
			return aes;
		}

		public async ValueTask<(bool success, string token)> AuthenticateBasic(string user, string password) {

			var credentials = await _data.GetUserCredential(KeyVaultCredentialType.Basic, user).NoSync();
			if (credentials.HasValue) {
				var basicCredential = JsonSerializer.Deserialize<BasicCredential>(credentials.Value.value);
				byte[] passwordData = basicCredential.Salt.Concat(Encoding.UTF8.GetBytes(password)).ToArray();
				byte[] passwordHash;
				using (var sha256 = SHA256.Create()) {
					passwordHash = sha256.ComputeHash(passwordData);
				}

				if (CommonUtility.AreByteArraysEqual(passwordHash, basicCredential.Password)) {
					return (false, null);
				}
			}
			else {
				credentials = await _data.GetUserCredential(KeyVaultCredentialType.BasicPlainText, user).NoSync();
				if (!credentials.HasValue || !string.Equals(password, credentials.Value.value, StringComparison.Ordinal)) {
					return (false, null);
				}
			}

			var userInfo = await _data.GetUserInformation(credentials.Value.usserId).NoSync();
			if (userInfo == null) {
				return (false, null);
			}

			List<Claim> claims = new List<Claim>();
			claims.Add(new Claim(KeyVaultClaims.UserId, userInfo.Id.ToString(CultureInfo.InvariantCulture)));
			claims.Add(new Claim(ClaimTypes.Name, userInfo.Name));
			foreach (var role in userInfo.Roles) {
				claims.Add(new Claim(ClaimTypes.Role, role));
			}

			return (true, GetTokenForUser(claims));
		}

		public async ValueTask<(bool success, string token)> AuthenticateWindows(ClaimsPrincipal user) {

			var credentials = await _data.GetUserCredential(KeyVaultCredentialType.Windows, user.Identity.Name).NoSync();
			if (credentials == null) {
				return (false, null);
			}

			var userInfo = await _data.GetUserInformation(credentials.Value.usserId).NoSync();

			List<Claim> claims = new List<Claim>();
			claims.Add(new Claim(KeyVaultClaims.UserId, userInfo.Id.ToString(CultureInfo.InvariantCulture)));
			claims.Add(new Claim(ClaimTypes.Name, userInfo.Name));
			foreach (var role in userInfo.Roles) {
				claims.Add(new Claim(ClaimTypes.Role, role));
			}

			return (true, GetTokenForUser(claims));
		}

		private string GetTokenForUser(List<Claim> claims) {
			var tokenCredentials = new SigningCredentials(GetSecurityKey(), SecurityAlgorithms.EcdsaSha256);
			var token = new JwtSecurityToken("KeyVault", "urn:target", claims, expires: DateTime.UtcNow.AddHours(2), signingCredentials: tokenCredentials);
			return GetJwtTokenHandler().WriteToken(token);
		}

		private sealed class BasicCredential {
			[JsonPropertyName("s")]
			public byte[] Salt { get; set; }
			[JsonPropertyName("p")]
			public byte[] Password { get; set; }
		}



		public async ValueTask<OperationResult<UserResult>> AddUser(ClaimsPrincipal user, NewUser newUser) {

			if (newUser == null) {
				return new OperationResult<UserResult> { ValidationFailed = true, ValidationMessage = "No data" };
			}
			else if (!(user.IsInRole(KeyVaultRoles.UserManagement) || user.IsInRole(KeyVaultRoles.Admin))) {
				return new OperationResult<UserResult> { Unauthorized = true };
			}
			else if (string.IsNullOrEmpty(newUser.Name)) {
				return new OperationResult<UserResult> { ValidationFailed = true, ValidationMessage = "[Name] is required" };
			}

			var userId = await _data.AddUser(newUser).NoSync();
			return new OperationResult<UserResult> { Created = true, Result = new UserResult { UserId = userId } };
		}

		public async ValueTask<OperationResult<UserData>> GetUser(ClaimsPrincipal user, long userId) {

			if (!(user.IsInRole(KeyVaultRoles.UserManagement) || user.IsInRole(KeyVaultRoles.Admin))) {
				return new OperationResult<UserData> { Unauthorized = true };
			}

			var userInfo = await _data.GetUserInformation(userId).NoSync();
			if (userInfo == null) {
				return new OperationResult<UserData> { NotFound = true };
			}

			return new OperationResult<UserData> { Result = new UserData { Name = userInfo.Name, UserId = userInfo.Id } };
		}

		public async ValueTask<OperationResult<CompletedResult>> UpdateUser(ClaimsPrincipal user, long userId, NewUser newUser) {

			if (newUser == null) {
				return new OperationResult<CompletedResult> { ValidationFailed = true, ValidationMessage = "No data" };
			}
			else if (!(user.IsInRole(KeyVaultRoles.UserManagement) || user.IsInRole(KeyVaultRoles.Admin))) {
				return new OperationResult<CompletedResult> { Unauthorized = true };
			}
			else if (string.IsNullOrEmpty(newUser.Name)) {
				return new OperationResult<CompletedResult> { ValidationFailed = true, ValidationMessage = "[Name] is required" };
			}

			var result = await _data.UpdateUser(userId, newUser).NoSync();
			return new OperationResult<CompletedResult> { Result = new CompletedResult { Completed = result } };
		}

		public async ValueTask<OperationResult<CompletedResult>> DeleteUser(ClaimsPrincipal user, long userId) {

			if (!(user.IsInRole(KeyVaultRoles.UserManagement) || user.IsInRole(KeyVaultRoles.Admin))) {
				return new OperationResult<CompletedResult> { Unauthorized = true };
			}

			var result = await _data.DeleteUser(userId).NoSync();
			return new OperationResult<CompletedResult> { Result = new CompletedResult { Completed = result } };
		}

		public async ValueTask<OperationResult<AllUsersResult>> GetUsers(ClaimsPrincipal user) {

			if (!(user.IsInRole(KeyVaultRoles.UserManagement) || user.IsInRole(KeyVaultRoles.Admin))) {
				return new OperationResult<AllUsersResult> { Unauthorized = true };
			}

			var users = await _data.GetUsers().NoSync();
			return new OperationResult<AllUsersResult> { Result = new AllUsersResult { Users = users.Select(z => new UserData { Name = z.Name, UserId = z.Id }).ToList() } };
		}



		public async ValueTask<OperationResult<UserRolesResult>> GetUserRoles(ClaimsPrincipal user, long userId) {

			if (!(user.IsInRole(KeyVaultRoles.UserManagement) || user.IsInRole(KeyVaultRoles.Admin))) {
				return new OperationResult<UserRolesResult> { Unauthorized = true };
			}

			var userInfo = await _data.GetUserInformation(userId).NoSync();
			if (userInfo == null) {
				return new OperationResult<UserRolesResult> { NotFound = true };
			}

			return new OperationResult<UserRolesResult> { Result = new UserRolesResult { Roles = userInfo.Roles.ToArray() } };
		}

		public async ValueTask<OperationResult<UserRolesResult>> MergeUserRoles(ClaimsPrincipal user, long userId, string[] roles) {
			bool isAdmin = user.IsInRole(KeyVaultRoles.Admin);
			if (!(isAdmin || user.IsInRole(KeyVaultRoles.UserManagement))) {
				return new OperationResult<UserRolesResult> { Unauthorized = true };
			}

			var userInfo = await _data.GetUserInformation(userId).NoSync();
			if (userInfo == null) {
				return new OperationResult<UserRolesResult> { NotFound = true };
			}

			HashSet<string> toAdd = new HashSet<string>();
			foreach (var role in roles) {
				// only roles that the current user has
				if (!isAdmin && !user.IsInRole(role)) {
					return new OperationResult<UserRolesResult> { Unauthorized = true };
				}
				if (!userInfo.Roles.Contains(role)) {
					toAdd.Add(role);
				}
			}

			if (toAdd.Count == 0) {
				return new OperationResult<UserRolesResult> { Result = new UserRolesResult { Roles = userInfo.Roles.ToArray() } };
			}

			await _data.AddUserRoles(userId, toAdd.ToArray()).NoSync();

			toAdd.AddRange(userInfo.Roles);
			return new OperationResult<UserRolesResult> { Result = new UserRolesResult { Roles = toAdd.ToArray() } };
		}

		public async ValueTask<OperationResult<UserRolesResult>> ReplaceUserRoles(ClaimsPrincipal user, long userId, string[] roles) {
			bool isAdmin = user.IsInRole(KeyVaultRoles.Admin);
			if (!(isAdmin || user.IsInRole(KeyVaultRoles.UserManagement))) {
				return new OperationResult<UserRolesResult> { Unauthorized = true };
			}

			var userInfo = await _data.GetUserInformation(userId).NoSync();
			if (userInfo == null) {
				return new OperationResult<UserRolesResult> { NotFound = true };
			}

			foreach (var role in roles) {
				// only roles that the current user has
				if (!isAdmin && !user.IsInRole(role)) {
					return new OperationResult<UserRolesResult> { Unauthorized = true };
				}
			}

			await _data.ReplaceUserRoles(userId, roles).NoSync();

			return new OperationResult<UserRolesResult> { Result = new UserRolesResult { Roles = roles.ToArray() } };
		}

		public async ValueTask<OperationResult<UserRolesResult>> DeleteUserRoles(ClaimsPrincipal user, long userId, string[] roles) {
			bool isAdmin = user.IsInRole(KeyVaultRoles.Admin);
			if (!(isAdmin || user.IsInRole(KeyVaultRoles.UserManagement))) {
				return new OperationResult<UserRolesResult> { Unauthorized = true };
			}

			var userInfo = await _data.GetUserInformation(userId).NoSync();
			if (userInfo == null) {
				return new OperationResult<UserRolesResult> { NotFound = true };
			}

			HashSet<string> toRemove = new HashSet<string>();
			foreach (var role in roles) {
				var hasRole = userInfo.Roles.Contains(role);
				if (hasRole) {
					// only roles that the current user has
					if (!isAdmin && !user.IsInRole(role)) {
						return new OperationResult<UserRolesResult> { Unauthorized = true };
					}
					toRemove.Add(role);
				}
			}

			if (toRemove.Count == 0) {
				return new OperationResult<UserRolesResult> { Result = new UserRolesResult { Roles = userInfo.Roles.ToArray() } };
			}

			await _data.RemoveUserRoles(userId, toRemove.ToArray()).NoSync();

			HashSet<string> remaining = new HashSet<string>(userInfo.Roles);
			foreach (var role in roles) {
				remaining.Remove(role);
			}
			return new OperationResult<UserRolesResult> { Result = new UserRolesResult { Roles = remaining.ToArray() } };
		}



		public async ValueTask<OperationResult<UserCredentialsResult>> GetCredentials(ClaimsPrincipal user, long userId) {

			if (!(user.IsInRole(KeyVaultRoles.UserManagement) || user.IsInRole(KeyVaultRoles.Admin))) {
				return new OperationResult<UserCredentialsResult> { Unauthorized = true };
			}

			var userInfo = await _data.GetUserInformation(userId).NoSync();
			if (userInfo == null) {
				return new OperationResult<UserCredentialsResult> { NotFound = true };
			}

			var credentials = await _data.GetUserCredentials(userId).NoSync();
			return new OperationResult<UserCredentialsResult> { Result = new UserCredentialsResult { Credentials = credentials.Select(z => new CredentialData { CredentialId = z.credentialId, CredentialType = z.type, Identifier = z.identifier }).ToList() } };
		}

		public async ValueTask<OperationResult<CompletedResult>> DeleteCredential(ClaimsPrincipal user, long userId, long credentialId) {

			if (!(user.IsInRole(KeyVaultRoles.UserManagement) || user.IsInRole(KeyVaultRoles.Admin))) {
				return new OperationResult<CompletedResult> { Unauthorized = true };
			}

			var userInfo = await _data.GetUserInformation(userId).NoSync();
			if (userInfo == null) {
				return new OperationResult<CompletedResult> { NotFound = true };
			}

			var credentials = await _data.GetUserCredentials(userId).NoSync();
			var index = credentials.FirstIndexOrNull(z => z.credentialId == credentialId);
			if (!index.HasValue) {
				return new OperationResult<CompletedResult> { NotFound = true };
			}

			var result = await _data.DeleteCredential(credentialId).NoSync();
			return new OperationResult<CompletedResult> { Result = new CompletedResult { Completed = result } };
		}

		public async ValueTask<OperationResult<CredentialResult>> AddWindowsCredential(ClaimsPrincipal user, long userId, string account) {
			if (!(user.IsInRole(KeyVaultRoles.UserManagement) || user.IsInRole(KeyVaultRoles.Admin))) {
				return new OperationResult<CredentialResult> { Unauthorized = true };
			}

			var userInfo = await _data.GetUserInformation(userId).NoSync();
			if (userInfo == null) {
				return new OperationResult<CredentialResult> { NotFound = true };
			}

			var credentials = await _data.GetUserCredentials(userId).NoSync();
			var index = credentials.FirstIndexOrNull(z => z.type == KeyVaultCredentialType.Windows && string.Equals(z.identifier, account, StringComparison.OrdinalIgnoreCase));
			if (index.HasValue) {
				return new OperationResult<CredentialResult> { Conflict = true };
			}

			var result = await _data.AddCredential(userId, KeyVaultCredentialType.Windows, account, null).NoSync();
			return new OperationResult<CredentialResult> { Created = true, Result = new CredentialResult { CredentialId = result } };
		}

		public async ValueTask<OperationResult<CredentialResult>> AddBasicCredential(ClaimsPrincipal user, long userId, string username, string password) {
			if (!(user.IsInRole(KeyVaultRoles.UserManagement) || user.IsInRole(KeyVaultRoles.Admin))) {
				return new OperationResult<CredentialResult> { Unauthorized = true };
			}

			var userInfo = await _data.GetUserInformation(userId).NoSync();
			if (userInfo == null) {
				return new OperationResult<CredentialResult> { NotFound = true };
			}

			var credentials = await _data.GetUserCredentials(userId).NoSync();
			var index = credentials.FirstIndexOrNull(z => z.type == KeyVaultCredentialType.Basic && string.Equals(z.identifier, username, StringComparison.OrdinalIgnoreCase));
			if (index.HasValue) {
				return new OperationResult<CredentialResult> { Conflict = true };
			}

			byte[] iv, data;
			using (var aes = GetAes()) {
				iv = aes.IV;
				using (var output = new MemoryStream()) {
					using (var crypto = new CryptoStream(output, aes.CreateEncryptor(), CryptoStreamMode.Write)) {
						crypto.Write(Encoding.UTF8.GetBytes(password));
					}
					data = output.ToArray();
				}
			}

			var credential = new BasicCredential {
				Password = data,
				Salt = iv
			};

			var result = await _data.AddCredential(userId, KeyVaultCredentialType.Basic, username, JsonSerializer.Serialize(credential)).NoSync();
			return new OperationResult<CredentialResult> { Created = true, Result = new CredentialResult { CredentialId = result } };
		}



		public async ValueTask<OperationResult<string>> GetSecretValue(ClaimsPrincipal user, string secretName, string name) {

			var secret = await _data.GetSecret(secretName).NoSync();
			if (secret == null) {
				return new OperationResult<string> { NotFound = true };
			}

			var userId = long.Parse(user.Claims.Single(z => z.Type == KeyVaultClaims.UserId).Value, NumberStyles.None, CultureInfo.InvariantCulture);
			var isAdmin = user.IsInRole(KeyVaultRoles.Admin);
			if (!(isAdmin || (secret.Access.TryGetValue(userId, out var access) && access.Read))) {
				return new OperationResult<string> { Unauthorized = true };
			}

			if (!secret.Data.ContainsKey(name ?? string.Empty)) {
				return new OperationResult<string> { NotFound = true };
			}

			var secretData = await _data.GetSecretData(secret.Id, name).NoSync();
			if (!secretData.HasValue) {
				// should never get here
				return new OperationResult<string> { NotFound = true };
			}

			byte[] plainData;
			using (var aes = GetAes()) {
				aes.IV = secretData.Value.iv;
				using (var output = new MemoryStream()) {
					using (var input = new MemoryStream(secretData.Value.value)) {
						using (var crypto = new CryptoStream(input, aes.CreateDecryptor(), CryptoStreamMode.Read)) {
							crypto.CopyTo(output);
						}
					}
					plainData = output.ToArray();
				}
			}

			string result;
			if (secretData.Value.type == KeyVaultSecretType.Text) {
				result = Encoding.UTF8.GetString(plainData);
			}
			else if (secretData.Value.type == KeyVaultSecretType.Blob) {
				result = Convert.ToBase64String(plainData);
			}
			else {
				throw new NotImplementedException(secretData.Value.type.ToString());
			}

			return new OperationResult<string> { Result = result };
		}

		public async ValueTask<OperationResult<(byte[] data, KeyVaultSecretType type)>> GetSecretValueAsBinrary(ClaimsPrincipal user, string secretName, string name) {

			var secret = await _data.GetSecret(secretName).NoSync();
			if (secret == null) {
				return new OperationResult<(byte[] data, KeyVaultSecretType type)> { NotFound = true };
			}

			var userId = long.Parse(user.Claims.Single(z => z.Type == KeyVaultClaims.UserId).Value, NumberStyles.None, CultureInfo.InvariantCulture);
			var isAdmin = user.IsInRole(KeyVaultRoles.Admin);
			if (!(isAdmin || (secret.Access.TryGetValue(userId, out var access) && access.Read))) {
				return new OperationResult<(byte[] data, KeyVaultSecretType type)> { Unauthorized = true };
			}

			if (!secret.Data.ContainsKey(name ?? string.Empty)) {
				return new OperationResult<(byte[] data, KeyVaultSecretType type)> { NotFound = true };
			}

			var secretData = await _data.GetSecretData(secret.Id, name).NoSync();
			if (!secretData.HasValue) {
				// should never get here
				return new OperationResult<(byte[] data, KeyVaultSecretType type)> { NotFound = true };
			}

			byte[] plainData;
			using (var aes = GetAes()) {
				aes.IV = secretData.Value.iv;
				using (var output = new MemoryStream()) {
					using (var input = new MemoryStream(secretData.Value.value)) {
						using (var crypto = new CryptoStream(input, aes.CreateDecryptor(), CryptoStreamMode.Read)) {
							crypto.CopyTo(output);
						}
					}
					plainData = output.ToArray();
				}
			}

			return new OperationResult<(byte[] data, KeyVaultSecretType type)> { Result = (plainData, secretData.Value.type) };
		}



		public async ValueTask<OperationResult<SecretItem>> GetSecret(ClaimsPrincipal user, string secretName) {
			bool isAdmin = user.IsInRole(KeyVaultRoles.Admin);
			if (isAdmin) {
				var secret = await _data.GetSecret(secretName).NoSync();
				if (secret == null) {
					return new OperationResult<SecretItem> { NotFound = true };
				}
				return new OperationResult<SecretItem> { Result = new SecretItem { SecretId = secret.Id, Name = secret.Name, Description = secret.Description } };
			}
			else if (user.IsInRole(KeyVaultRoles.ListSecrets)) {
				var secret = await _data.GetSecret(secretName).NoSync();
				if (secret == null) {
					return new OperationResult<SecretItem> { NotFound = true };
				}
				var userId = long.Parse(user.Claims.Single(z => z.Type == KeyVaultClaims.UserId).Value, NumberStyles.None, CultureInfo.InvariantCulture);
				if (!(secret.Access.TryGetValue(userId, out var access) && (access.Read || access.Write || access.Assign))) {
					return new OperationResult<SecretItem> { Unauthorized = true };
				}
				return new OperationResult<SecretItem> { Result = new SecretItem { SecretId = secret.Id, Name = secret.Name, Description = secret.Description } };
			}
			else {
				return new OperationResult<SecretItem> { Unauthorized = true };
			}
		}

		public async ValueTask<OperationResult<SecretResult>> NewSecret(ClaimsPrincipal user, NewSecret newSecret) {

			if (newSecret == null) {
				return new OperationResult<SecretResult> { ValidationFailed = true, ValidationMessage = "No data" };
			}
			else if (!(user.IsInRole(KeyVaultRoles.CreateSecret) || user.IsInRole(KeyVaultRoles.Admin))) {
				return new OperationResult<SecretResult> { Unauthorized = true };
			}
			else if (string.IsNullOrEmpty(newSecret.Name)) {
				return new OperationResult<SecretResult> { ValidationFailed = true, ValidationMessage = "[SecretName] is required" };
			}

			var userId = long.Parse(user.Claims.Single(z => z.Type == KeyVaultClaims.UserId).Value, NumberStyles.None, CultureInfo.InvariantCulture);
			long secretId = await _data.CreateSecret(userId, newSecret.Name, newSecret.Description).NoSync();
			return new OperationResult<SecretResult> { Created = true, Result = new SecretResult { SecretId = secretId } };
		}

		public async ValueTask<OperationResult<SecretResult>> UpdateSecretDescription(ClaimsPrincipal user, string secretName, UpdateSecretDescription data) {

			if (data == null) {
				return new OperationResult<SecretResult> { ValidationFailed = true, ValidationMessage = "No data" };
			}

			var secret = await _data.GetSecret(secretName).NoSync();
			if (secret == null) {
				return new OperationResult<SecretResult> { NotFound = true };
			}

			// check access
			var userId = long.Parse(user.Claims.Single(z => z.Type == KeyVaultClaims.UserId).Value, NumberStyles.None, CultureInfo.InvariantCulture);
			bool isAdmin = user.IsInRole(KeyVaultRoles.Admin);
			if (!(isAdmin || (secret.Access.TryGetValue(userId, out var access) && access.Write))) {
				return new OperationResult<SecretResult> { Unauthorized = true };
			}

			long secretId = await _data.UpdateSecretDescription(userId, secretName, data.Description);
			return new OperationResult<SecretResult> { Result = new SecretResult { SecretId = secretId } };
		}

		public async ValueTask<OperationResult<CompletedResult>> DeleteSecret(ClaimsPrincipal user, string secretName) {

			if (string.IsNullOrEmpty(secretName)) {
				return new OperationResult<CompletedResult> { ValidationFailed = true, ValidationMessage = "[SecretName] is required" };
			}

			var secret = await _data.GetSecret(secretName).NoSync();
			if (secret == null) {
				return new OperationResult<CompletedResult> { NotFound = true };
			}

			// check access
			var userId = long.Parse(user.Claims.Single(z => z.Type == KeyVaultClaims.UserId).Value, NumberStyles.None, CultureInfo.InvariantCulture);
			bool isAdmin = user.IsInRole(KeyVaultRoles.Admin);
			if (!(isAdmin || (secret.Access.TryGetValue(userId, out var access) && access.Write))) {
				return new OperationResult<CompletedResult> { Unauthorized = true };
			}

			var result = await _data.DeleteSecret(userId, secretName).NoSync();
			return new OperationResult<CompletedResult> { Result = new CompletedResult { Completed = result } };
		}

		public async ValueTask<OperationResult<AllSecretsResult>> GetAllSecrets(ClaimsPrincipal user) {
			bool isAdmin = user.IsInRole(KeyVaultRoles.Admin);
			if (isAdmin) {
				var result = await _data.GetSecrets().NoSync();
				return new OperationResult<AllSecretsResult> { Result = new AllSecretsResult { Secrets = result.Select(z => new SecretItem { SecretId = z.secretId, Name = z.name, Description = z.description }).ToList() } };
			}
			else if (user.IsInRole(KeyVaultRoles.ListSecrets)) {
				var userId = long.Parse(user.Claims.Single(z => z.Type == KeyVaultClaims.UserId).Value, NumberStyles.None, CultureInfo.InvariantCulture);
				var result = await _data.GetSecrets(userId).NoSync();
				return new OperationResult<AllSecretsResult> { Result = new AllSecretsResult { Secrets = result.Select(z => new SecretItem { SecretId = z.secretId, Name = z.name, Description = z.description }).ToList() } };
			}
			else {
				return new OperationResult<AllSecretsResult> { Unauthorized = true };
			}
		}



		public async ValueTask<OperationResult<CompletedResult>> NewSecretData(ClaimsPrincipal user, string secretName, NewSecretData data) {

			if (data == null) {
				return new OperationResult<CompletedResult> { ValidationFailed = true, ValidationMessage = "No data" };
			}
			else if (string.IsNullOrEmpty(secretName)) {
				return new OperationResult<CompletedResult> { ValidationFailed = true, ValidationMessage = "[SecretName] is required" };
			}
			else if (!(user.IsInRole(KeyVaultRoles.CreateSecret) || user.IsInRole(KeyVaultRoles.Admin))) {
				return new OperationResult<CompletedResult> { Unauthorized = true };
			}
			else if (string.IsNullOrEmpty(data.Value)) {
				return new OperationResult<CompletedResult> { ValidationFailed = true, ValidationMessage = "[Value] is required" };
			}
			else if (!data.SecretType.HasValue) {
				return new OperationResult<CompletedResult> { ValidationFailed = true, ValidationMessage = "[SecretType] is required" };
			}

			byte[] plainData;
			if (data.SecretType == KeyVaultSecretType.Text) {
				plainData = Encoding.UTF8.GetBytes(data.Value);
			}
			else if (data.SecretType == KeyVaultSecretType.Blob) {
				try {
					plainData = Convert.FromBase64String(data.Value);
				}
				catch (Exception ex) {
					return new OperationResult<CompletedResult> { ValidationFailed = true, ValidationMessage = "Invalid [Value] for specified [SecretType]" };
				}
			}
			else {
				throw new NotImplementedException(data.SecretType.ToString());
			}

			var secret = await _data.GetSecret(secretName).NoSync();
			if (secret == null) {
				return new OperationResult<CompletedResult> { NotFound = true };
			}

			if (secret.Data.ContainsKey(data.Name ?? string.Empty)) {
				return new OperationResult<CompletedResult> { Conflict = true };
			}

			byte[] secretData;
			byte[] iv;
			using (var aes = GetAes()) {
				iv = aes.IV;
				using (var output = new MemoryStream()) {
					using (var crypto = new CryptoStream(output, aes.CreateEncryptor(), CryptoStreamMode.Write)) {
						crypto.Write(plainData);
					}
					secretData = output.ToArray();
				}
			}

			var userId = long.Parse(user.Claims.Single(z => z.Type == KeyVaultClaims.UserId).Value, NumberStyles.None, CultureInfo.InvariantCulture);
			var result = await _data.AddSecretData(userId, secret.Id, data.Name, data.Description, data.SecretType.Value, secretData, iv).NoSync();
			return new OperationResult<CompletedResult> { Created = true, Result = new CompletedResult { Completed = result } };
		}

		public async ValueTask<OperationResult<CompletedResult>> UpdateSecretDataDescription(ClaimsPrincipal user, string secretName, string name, UpdateSecretDataDescription data) {

			if (data == null) {
				return new OperationResult<CompletedResult> { ValidationFailed = true, ValidationMessage = "No data" };
			}
			else if (string.IsNullOrEmpty(secretName)) {
				return new OperationResult<CompletedResult> { ValidationFailed = true, ValidationMessage = "[SecretName] is required" };
			}

			var secret = await _data.GetSecret(secretName).NoSync();
			if (secret == null) {
				return new OperationResult<CompletedResult> { NotFound = true };
			}

			if (!secret.Data.ContainsKey(name ?? string.Empty)) {
				return new OperationResult<CompletedResult> { NotFound = true };
			}

			// check access
			var userId = long.Parse(user.Claims.Single(z => z.Type == KeyVaultClaims.UserId).Value, NumberStyles.None, CultureInfo.InvariantCulture);
			bool isAdmin = user.IsInRole(KeyVaultRoles.Admin);
			if (!(isAdmin || (secret.Access.TryGetValue(userId, out var access) && access.Write))) {
				return new OperationResult<CompletedResult> { Unauthorized = true };
			}

			var result = await _data.UpdateSecretDataDescription(userId, secret.Id, name, data.Description).NoSync();
			return new OperationResult<CompletedResult> { Result = new CompletedResult { Completed = result } };
		}

		public async ValueTask<OperationResult<CompletedResult>> UpdateSecretData(ClaimsPrincipal user, string secretName, string name, UpdateSecretData data) {

			if (data == null) {
				return new OperationResult<CompletedResult> { ValidationFailed = true, ValidationMessage = "No data" };
			}
			else if (string.IsNullOrEmpty(secretName)) {
				return new OperationResult<CompletedResult> { ValidationFailed = true, ValidationMessage = "[SecretName] is required" };
			}
			else if (!data.SecretType.HasValue) {
				return new OperationResult<CompletedResult> { ValidationFailed = true, ValidationMessage = "[SecretType] is required" };
			}
			else if (string.IsNullOrEmpty(data.Value)) {
				return new OperationResult<CompletedResult> { ValidationFailed = true, ValidationMessage = "[Value] is required" };
			}

			byte[] plainData;
			if (data.SecretType == KeyVaultSecretType.Text) {
				plainData = Encoding.UTF8.GetBytes(data.Value);
			}
			else if (data.SecretType == KeyVaultSecretType.Blob) {
				try {
					plainData = Convert.FromBase64String(data.Value);
				}
				catch (Exception ex) {
					return new OperationResult<CompletedResult> { ValidationFailed = true, ValidationMessage = "Invalid [Value] for specified [SecretType]" };
				}
			}
			else {
				throw new NotImplementedException(data.SecretType.ToString());
			}

			var secret = await _data.GetSecret(secretName).NoSync();
			if (secret == null) {
				return new OperationResult<CompletedResult> { NotFound = true };
			}

			if (!secret.Data.ContainsKey(name ?? string.Empty)) {
				return new OperationResult<CompletedResult> { NotFound = true };
			}

			// check access
			var userId = long.Parse(user.Claims.Single(z => z.Type == KeyVaultClaims.UserId).Value, NumberStyles.None, CultureInfo.InvariantCulture);
			bool isAdmin = user.IsInRole(KeyVaultRoles.Admin);
			if (!(isAdmin || (secret.Access.TryGetValue(userId, out var access) && access.Write))) {
				return new OperationResult<CompletedResult> { Unauthorized = true };
			}

			byte[] secretData;
			byte[] iv;
			using (var aes = GetAes()) {
				iv = aes.IV;
				using (var output = new MemoryStream()) {
					using (var crypto = new CryptoStream(output, aes.CreateEncryptor(), CryptoStreamMode.Write)) {
						crypto.Write(plainData);
					}
					secretData = output.ToArray();
				}
			}


			var result = await _data.UpdateSecretData(userId, secret.Id, name, data.SecretType.Value, secretData, iv).NoSync();
			return new OperationResult<CompletedResult> { Result = new CompletedResult { Completed = result } };
		}

		public async ValueTask<OperationResult<CompletedResult>> DeleteSecretData(ClaimsPrincipal user, string secretName, string name) {

			if (string.IsNullOrEmpty(secretName)) {
				return new OperationResult<CompletedResult> { ValidationFailed = true, ValidationMessage = "[SecretName] is required" };
			}

			var secret = await _data.GetSecret(secretName).NoSync();
			if (secret == null) {
				return new OperationResult<CompletedResult> { NotFound = true };
			}

			if (!secret.Data.ContainsKey(name ?? string.Empty)) {
				return new OperationResult<CompletedResult> { NotFound = true };
			}

			// check access
			var userId = long.Parse(user.Claims.Single(z => z.Type == KeyVaultClaims.UserId).Value, NumberStyles.None, CultureInfo.InvariantCulture);
			bool isAdmin = user.IsInRole(KeyVaultRoles.Admin);
			if (!(isAdmin || (secret.Access.TryGetValue(userId, out var access) && access.Write))) {
				return new OperationResult<CompletedResult> { Unauthorized = true };
			}

			var result = await _data.DeleteSecretData(userId, secret.Id, name).NoSync();
			return new OperationResult<CompletedResult> { Result = new CompletedResult { Completed = result } };
		}

		public async ValueTask<OperationResult<SecretDataItem>> GetSecretData(ClaimsPrincipal user, string secretName, string name) {

			if (string.IsNullOrEmpty(secretName)) {
				return new OperationResult<SecretDataItem> { ValidationFailed = true, ValidationMessage = "[SecretName] is required" };
			}

			var secret = await _data.GetSecret(secretName).NoSync();
			if (secret == null) {
				return new OperationResult<SecretDataItem> { NotFound = true };
			}
			if (!secret.Data.TryGetValue(name ?? string.Empty, out var data)) {
				return new OperationResult<SecretDataItem> { NotFound = true };
			}

			// check access
			var userId = long.Parse(user.Claims.Single(z => z.Type == KeyVaultClaims.UserId).Value, NumberStyles.None, CultureInfo.InvariantCulture);
			bool isAdmin = user.IsInRole(KeyVaultRoles.Admin);
			if (!(isAdmin || (user.IsInRole(KeyVaultRoles.ListSecrets) && secret.Access.TryGetValue(userId, out var access) && (access.Read || access.Write || access.Assign)))) {
				return new OperationResult<SecretDataItem> { Unauthorized = true };
			}

			var result = await _data.GetSecretData(secret.Id).NoSync();
			return new OperationResult<SecretDataItem> { Result = new SecretDataItem { Name = data.Name, Description = data.Description, SecretType = data.SecretType } };

		}

		public async ValueTask<OperationResult<AllSecretData>> GetSecretDataForSecret(ClaimsPrincipal user, string secretName) {

			if (string.IsNullOrEmpty(secretName)) {
				return new OperationResult<AllSecretData> { ValidationFailed = true, ValidationMessage = "[SecretName] is required" };
			}

			var secret = await _data.GetSecret(secretName).NoSync();
			if (secret == null) {
				return new OperationResult<AllSecretData> { NotFound = true };
			}

			// check access
			var userId = long.Parse(user.Claims.Single(z => z.Type == KeyVaultClaims.UserId).Value, NumberStyles.None, CultureInfo.InvariantCulture);
			bool isAdmin = user.IsInRole(KeyVaultRoles.Admin);
			if (!(isAdmin || (user.IsInRole(KeyVaultRoles.ListSecrets) && secret.Access.TryGetValue(userId, out var access) && (access.Read || access.Write || access.Assign)))) {
				return new OperationResult<AllSecretData> { Unauthorized = true };
			}

			var result = await _data.GetSecretData(secret.Id).NoSync();
			return new OperationResult<AllSecretData> { Result = new AllSecretData { Data = result.Select(z => new SecretDataItem { Name = z.name, Description = z.description, SecretType = z.type }).ToList() } };
		}



		public async ValueTask<OperationResult<SecretAccessResult>> GetSecretAccess(ClaimsPrincipal user, string secretName) {

			if (string.IsNullOrEmpty(secretName)) {
				return new OperationResult<SecretAccessResult> { ValidationFailed = true, ValidationMessage = "[SecretName] is required" };
			}

			var secret = await _data.GetSecret(secretName).NoSync();
			if (secret == null) {
				return new OperationResult<SecretAccessResult> { NotFound = true };
			}

			// check access
			var userId = long.Parse(user.Claims.Single(z => z.Type == KeyVaultClaims.UserId).Value, NumberStyles.None, CultureInfo.InvariantCulture);
			bool isAdmin = user.IsInRole(KeyVaultRoles.Admin);
			if (!(isAdmin || (secret.Access.TryGetValue(userId, out var access) && access.Assign))) {
				return new OperationResult<SecretAccessResult> { Unauthorized = true };
			}

			return new OperationResult<SecretAccessResult> { Result = new SecretAccessResult() { Access = secret.Access.Select(a => new AccessData { UserId = a.Key, Read = a.Value.Read, Write = a.Value.Write, Assign = a.Value.Write }).ToList() } };
		}

		public async ValueTask<OperationResult<CompletedResult>> DeleteSecretAccess(ClaimsPrincipal user, string secretName, long userId) {

			if (string.IsNullOrEmpty(secretName)) {
				return new OperationResult<CompletedResult> { ValidationFailed = true, ValidationMessage = "[SecretName] is required" };
			}

			var secret = await _data.GetSecret(secretName).NoSync();
			if (secret == null) {
				return new OperationResult<CompletedResult> { NotFound = true };
			}

			// check access
			var currentUserId = long.Parse(user.Claims.Single(z => z.Type == KeyVaultClaims.UserId).Value, NumberStyles.None, CultureInfo.InvariantCulture);
			bool isAdmin = user.IsInRole(KeyVaultRoles.Admin);
			if (!(isAdmin || (secret.Access.TryGetValue(currentUserId, out var access) && access.Assign))) {
				return new OperationResult<CompletedResult> { Unauthorized = true };
			}

			var result = await _data.DeleteSecretAccess(secret.Id, userId).NoSync();
			return new OperationResult<CompletedResult> { Result = new CompletedResult { Completed = result } };
		}

		public async ValueTask<OperationResult<CompletedResult>> AddSecretAccess(ClaimsPrincipal user, string secretName, long userId, NewAccessData data) {

			if (string.IsNullOrEmpty(secretName)) {
				return new OperationResult<CompletedResult> { ValidationFailed = true, ValidationMessage = "[SecretName] is required" };
			}
			else if (!data.Read && !data.Write && !data.Assign) {
				return new OperationResult<CompletedResult> { ValidationFailed = true, ValidationMessage = "Specify [Read] and/or [Write] and/or [Assign] access for [SecretName] or delete the access" };
			}

			var secret = await _data.GetSecret(secretName).NoSync();
			if (secret == null) {
				return new OperationResult<CompletedResult> { NotFound = true };
			}

			// check access
			var currentUserId = long.Parse(user.Claims.Single(z => z.Type == KeyVaultClaims.UserId).Value, NumberStyles.None, CultureInfo.InvariantCulture);
			bool isAdmin = user.IsInRole(KeyVaultRoles.Admin);
			if (!(isAdmin || (secret.Access.TryGetValue(currentUserId, out var access) && access.Assign))) {
				return new OperationResult<CompletedResult> { Unauthorized = true };
			}

			if (secret.Access.ContainsKey(userId)) {
				return new OperationResult<CompletedResult> { Conflict = true };
			}

			var result = await _data.AddSecretAccess(secret.Id, userId, data.Read, data.Write, data.Assign).NoSync();
			return new OperationResult<CompletedResult> { Result = new CompletedResult { Completed = result } };
		}

		public async ValueTask<OperationResult<CompletedResult>> AddOrUpdateSecretAccess(ClaimsPrincipal user, string secretName, long userId, NewAccessData data) {

			if (string.IsNullOrEmpty(secretName)) {
				return new OperationResult<CompletedResult> { ValidationFailed = true, ValidationMessage = "[SecretName] is required" };
			}
			else if (!data.Read && !data.Write && !data.Assign) {
				return new OperationResult<CompletedResult> { ValidationFailed = true, ValidationMessage = "Specify [Read] and/or [Write] and/or [Assign] access for [SecretName] or delete the access" };
			}

			var secret = await _data.GetSecret(secretName).NoSync();
			if (secret == null) {
				return new OperationResult<CompletedResult> { NotFound = true };
			}

			// check access
			var currentUserId = long.Parse(user.Claims.Single(z => z.Type == KeyVaultClaims.UserId).Value, NumberStyles.None, CultureInfo.InvariantCulture);
			bool isAdmin = user.IsInRole(KeyVaultRoles.Admin);
			if (!(isAdmin || (secret.Access.TryGetValue(currentUserId, out var access) && access.Assign))) {
				return new OperationResult<CompletedResult> { Unauthorized = true };
			}

			var result = await _data.AddOrUpdateSecretAccess(secret.Id, userId, data.Read, data.Write, data.Assign).NoSync();
			return new OperationResult<CompletedResult> { Result = new CompletedResult { Completed = result } };
		}



		public async ValueTask<OperationResult<AllSecretsResult>> GetSecretsWithNoAccess(ClaimsPrincipal user) {

			if (!user.IsInRole(KeyVaultRoles.Admin)) {
				return new OperationResult<AllSecretsResult> { Unauthorized = true };
			}

			var result = await _data.GetSecretsWithNoAccess().NoSync();
			return new OperationResult<AllSecretsResult> { Result = new AllSecretsResult { Secrets = result.Select(z => new SecretItem { SecretId = z.secretId, Name = z.name, Description = z.description }).ToList() } };
		}

		public async ValueTask<OperationResult<CompletedResult>> DeleteSecretsWithNoAccess(ClaimsPrincipal user) {

			if (!user.IsInRole(KeyVaultRoles.Admin)) {
				return new OperationResult<CompletedResult> { Unauthorized = true };
			}

			var result = await _data.DeleteSecretsWithNoAccess().NoSync();
			return new OperationResult<CompletedResult> { Result = new CompletedResult { Completed = result } };
		}

	}
}
