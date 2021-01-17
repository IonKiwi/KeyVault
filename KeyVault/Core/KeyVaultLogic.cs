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
				// only roles that the current user has
				if (!isAdmin && !user.IsInRole(role)) {
					return new OperationResult<UserRolesResult> { Unauthorized = true };
				}
				if (userInfo.Roles.Contains(role)) {
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

		public async ValueTask<OperationResult<string>> GetSecret(ClaimsPrincipal user, string name) {

			var secret = await _data.GetSecret(name).NoSync();
			if (secret == null) {
				return new OperationResult<string> { NotFound = true };
			}

			var userId = long.Parse(user.Claims.Single(z => z.Type == KeyVaultClaims.UserId).Value, NumberStyles.None, CultureInfo.InvariantCulture);
			var isAdmin = user.IsInRole(KeyVaultRoles.Admin);
			if (!isAdmin || !secret.Access.TryGetValue(userId, out var access) || !access.Read) {
				return new OperationResult<string> { Unauthorized = true };
			}

			byte[] plainData;
			using (var aes = GetAes()) {
				aes.IV = secret.IV;
				using (var output = new MemoryStream()) {
					using (var input = new MemoryStream(secret.Value)) {
						using (var crypto = new CryptoStream(input, aes.CreateDecryptor(), CryptoStreamMode.Read)) {
							crypto.CopyTo(output);
						}
					}
					plainData = output.ToArray();
				}
			}

			string result;
			if (secret.SecretType == KeyVaultSecretType.Text) {
				result = Encoding.UTF8.GetString(plainData);
			}
			else if (secret.SecretType == KeyVaultSecretType.Blob) {
				result = Convert.ToBase64String(plainData);
			}
			else {
				throw new NotImplementedException(secret.SecretType.ToString());
			}

			return new OperationResult<string> { Result = result };
		}

		public async ValueTask<OperationResult<SecretResult>> NewSecret(ClaimsPrincipal user, NewSecret newSecret) {

			if (newSecret == null) {
				return new OperationResult<SecretResult> { ValidationFailed = true, ValidationMessage = "No data" };
			}
			else if (!(user.IsInRole(KeyVaultRoles.CreateSecret) || user.IsInRole(KeyVaultRoles.Admin))) {
				return new OperationResult<SecretResult> { Unauthorized = true };
			}
			else if (string.IsNullOrEmpty(newSecret.Name)) {
				return new OperationResult<SecretResult> { ValidationFailed = true, ValidationMessage = "[Name] is required" };
			}
			else if (string.IsNullOrEmpty(newSecret.SecretType)) {
				return new OperationResult<SecretResult> { ValidationFailed = true, ValidationMessage = "[SecretType] is required" };
			}
			else if (string.IsNullOrEmpty(newSecret.Value)) {
				return new OperationResult<SecretResult> { ValidationFailed = true, ValidationMessage = "[Value] is required" };
			}

			if (!CommonUtility.TryParseEnum(newSecret.SecretType, out KeyVaultSecretType secretType)) {
				return new OperationResult<SecretResult> { ValidationFailed = true, ValidationMessage = "Invalid [SecretType]" };
			}

			byte[] plainData;
			if (secretType == KeyVaultSecretType.Text) {
				plainData = Encoding.UTF8.GetBytes(newSecret.Value);
			}
			else if (secretType == KeyVaultSecretType.Blob) {
				try {
					plainData = Convert.FromBase64String(newSecret.Value);
				}
				catch (Exception ex) {
					return new OperationResult<SecretResult> { ValidationFailed = true, ValidationMessage = "Invalid [Value] for specified [SecretType]" };
				}
			}
			else {
				throw new NotImplementedException(secretType.ToString());
			}

			var secret = await _data.GetSecret(newSecret.Name).NoSync();
			if (secret != null) {
				return new OperationResult<SecretResult> { Conflict = true };
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
			long secretId = await _data.CreateSecret(userId, newSecret.Name, secretType, secretData, iv).NoSync();
			return new OperationResult<SecretResult> { Created = true, Result = new SecretResult { SecretId = secretId } };
		}

		public async ValueTask<OperationResult<SecretResult>> UpdateSecret(ClaimsPrincipal user, string secretName, NewSecretData data) {

			if (data == null) {
				return new OperationResult<SecretResult> { ValidationFailed = true, ValidationMessage = "No data" };
			}
			else if (string.IsNullOrEmpty(secretName)) {
				return new OperationResult<SecretResult> { ValidationFailed = true, ValidationMessage = "[Name] is required" };
			}
			else if (string.IsNullOrEmpty(data.SecretType)) {
				return new OperationResult<SecretResult> { ValidationFailed = true, ValidationMessage = "[SecretType] is required" };
			}
			else if (string.IsNullOrEmpty(data.Value)) {
				return new OperationResult<SecretResult> { ValidationFailed = true, ValidationMessage = "[Value] is required" };
			}

			if (!CommonUtility.TryParseEnum(data.SecretType, out KeyVaultSecretType secretType)) {
				return new OperationResult<SecretResult> { ValidationFailed = true, ValidationMessage = "Invalid [SecretType]" };
			}

			byte[] plainData;
			if (secretType == KeyVaultSecretType.Text) {
				plainData = Encoding.UTF8.GetBytes(data.Value);
			}
			else if (secretType == KeyVaultSecretType.Blob) {
				try {
					plainData = Convert.FromBase64String(data.Value);
				}
				catch (Exception ex) {
					return new OperationResult<SecretResult> { ValidationFailed = true, ValidationMessage = "Invalid [Value] for specified [SecretType]" };
				}
			}
			else {
				throw new NotImplementedException(secretType.ToString());
			}

			var secret = await _data.GetSecret(secretName).NoSync();
			if (secret != null) {
				return new OperationResult<SecretResult> { NotFound = true };
			}

			// check access
			var userId = long.Parse(user.Claims.Single(z => z.Type == KeyVaultClaims.UserId).Value, NumberStyles.None, CultureInfo.InvariantCulture);
			bool isAdmin = user.IsInRole(KeyVaultRoles.Admin);
			if (!isAdmin || !secret.Access.TryGetValue(userId, out var access) || !access.Write) {
				return new OperationResult<SecretResult> { Unauthorized = true };
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


			long secretId = await _data.UpdateSecret(userId, secretName, secretType, secretData, iv).NoSync();
			return new OperationResult<SecretResult> { Result = new SecretResult { SecretId = secretId } };
		}

		public async ValueTask<OperationResult<CompletedResult>> DeleteSecret(ClaimsPrincipal user, string name) {

			if (string.IsNullOrEmpty(name)) {
				return new OperationResult<CompletedResult> { ValidationFailed = true, ValidationMessage = "[Name] is required" };
			}

			var secret = await _data.GetSecret(name).NoSync();
			if (secret != null) {
				return new OperationResult<CompletedResult> { NotFound = true };
			}

			// check access
			var userId = long.Parse(user.Claims.Single(z => z.Type == KeyVaultClaims.UserId).Value, NumberStyles.None, CultureInfo.InvariantCulture);
			bool isAdmin = user.IsInRole(KeyVaultRoles.Admin);
			if (!isAdmin || !secret.Access.TryGetValue(userId, out var access) || !access.Write) {
				return new OperationResult<CompletedResult> { Unauthorized = true };
			}

			var result = await _data.DeleteSecret(userId, name).NoSync();
			return new OperationResult<CompletedResult> { Result = new CompletedResult { Completed = result } };
		}

		public async ValueTask<OperationResult<AllSecretsResult>> GetSecretsWithNoAccess(ClaimsPrincipal user) {

			if (!user.IsInRole(KeyVaultRoles.Admin)) {
				return new OperationResult<AllSecretsResult> { Unauthorized = true };
			}

			var result = await _data.GetSecretsWithNoAccess().NoSync();
			return new OperationResult<AllSecretsResult> { Result = new AllSecretsResult { Secrets = result } };
		}

		public async ValueTask<OperationResult<CompletedResult>> DeleteSecretsWithNoAccess(ClaimsPrincipal user) {

			if (!user.IsInRole(KeyVaultRoles.Admin)) {
				return new OperationResult<CompletedResult> { Unauthorized = true };
			}

			var result = await _data.DeleteSecretsWithNoAccess().NoSync();
			return new OperationResult<CompletedResult> { Result = new CompletedResult { Completed = result } };
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
			return new OperationResult<UserCredentialsResult> { Result = new UserCredentialsResult { Credentials = credentials } };
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

		public async ValueTask<OperationResult<SecretAccessResult>> GetSecretAccess(ClaimsPrincipal user, string secretName) {

			if (string.IsNullOrEmpty(secretName)) {
				return new OperationResult<SecretAccessResult> { ValidationFailed = true, ValidationMessage = "[SecretName] is required" };
			}

			var secret = await _data.GetSecret(secretName).NoSync();
			if (secret != null) {
				return new OperationResult<SecretAccessResult> { NotFound = true };
			}

			// check access
			var userId = long.Parse(user.Claims.Single(z => z.Type == KeyVaultClaims.UserId).Value, NumberStyles.None, CultureInfo.InvariantCulture);
			bool isAdmin = user.IsInRole(KeyVaultRoles.Admin);
			if (!isAdmin || !secret.Access.TryGetValue(userId, out var access) || !access.Assign) {
				return new OperationResult<SecretAccessResult> { Unauthorized = true };
			}

			return new OperationResult<SecretAccessResult> { Result = new SecretAccessResult() { Access = secret.Access.Select(a => new AccessData { UserId = a.Key, Read = a.Value.Read, Write = a.Value.Write, Assign = a.Value.Write }).ToList() } };
		}

		public async ValueTask<OperationResult<CompletedResult>> DeleteSecretAccess(ClaimsPrincipal user, string secretName, long userId) {

			if (string.IsNullOrEmpty(secretName)) {
				return new OperationResult<CompletedResult> { ValidationFailed = true, ValidationMessage = "[SecretName] is required" };
			}

			var secret = await _data.GetSecret(secretName).NoSync();
			if (secret != null) {
				return new OperationResult<CompletedResult> { NotFound = true };
			}

			// check access
			var currentUserId = long.Parse(user.Claims.Single(z => z.Type == KeyVaultClaims.UserId).Value, NumberStyles.None, CultureInfo.InvariantCulture);
			bool isAdmin = user.IsInRole(KeyVaultRoles.Admin);
			if (!isAdmin || !secret.Access.TryGetValue(currentUserId, out var access) || !access.Assign) {
				return new OperationResult<CompletedResult> { Unauthorized = true };
			}

			var result = await _data.DeleteSecretAccess(secret.Id, userId).NoSync();
			return new OperationResult<CompletedResult> { Result = new CompletedResult { Completed = result } };
		}

		public async ValueTask<OperationResult<CompletedResult>> AddOrUpdateSecretAccess(ClaimsPrincipal user, string secretName, long userId, NewAccessData data) {

			if (string.IsNullOrEmpty(secretName)) {
				return new OperationResult<CompletedResult> { ValidationFailed = true, ValidationMessage = "[SecretName] is required" };
			}

			var secret = await _data.GetSecret(secretName).NoSync();
			if (secret != null) {
				return new OperationResult<CompletedResult> { NotFound = true };
			}

			// check access
			var currentUserId = long.Parse(user.Claims.Single(z => z.Type == KeyVaultClaims.UserId).Value, NumberStyles.None, CultureInfo.InvariantCulture);
			bool isAdmin = user.IsInRole(KeyVaultRoles.Admin);
			if (!isAdmin || !secret.Access.TryGetValue(currentUserId, out var access) || !access.Assign) {
				return new OperationResult<CompletedResult> { Unauthorized = true };
			}

			var result = await _data.AddOrUpdateSecretAccess(secret.Id, userId, data.Read, data.Write, data.Assign).NoSync();
			return new OperationResult<CompletedResult> { Result = new CompletedResult { Completed = result } };
		}
	}
}
