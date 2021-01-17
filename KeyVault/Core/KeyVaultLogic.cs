using KeyVault.Config;
using KeyVault.Data;
using KeyVault.Extensions;
using KeyVault.Utilities;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace KeyVault.Core {
	public sealed class KeyVaultLogic {

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

		public async ValueTask<OperationResult<long>> AddUser(ClaimsPrincipal user, NewUser newUser) {

			if (newUser == null) {
				return new OperationResult<long> { ValidationFailed = true, ValidationMessage = "No data" };
			}
			else if (!(user.IsInRole("UserManagement") || user.IsInRole("Admin"))) {
				return new OperationResult<long> { Unauthorized = true };
			}
			else if (string.IsNullOrEmpty(newUser.Name)) {
				return new OperationResult<long> { ValidationFailed = true, ValidationMessage = "[Name] is required" };
			}

			var userId = await _data.AddUser(newUser).NoSync();
			return new OperationResult<long> { Result = userId };
		}

		public async ValueTask<OperationResult<UserData>> GetUser(ClaimsPrincipal user, long userId) {

			if (!(user.IsInRole("UserManagement") || user.IsInRole("Admin"))) {
				return new OperationResult<UserData> { Unauthorized = true };
			}

			var userInfo = await _data.GetUserInformation(userId).NoSync();
			if (userInfo == null) {
				return new OperationResult<UserData> { NotFound = true };
			}

			return new OperationResult<UserData> { Result = new UserData { Name = userInfo.Name, UserId = userInfo.Id } };
		}

		public async ValueTask<OperationResult<string[]>> GetUserRoles(ClaimsPrincipal user, long userId) {

			if (!(user.IsInRole("UserManagement") || user.IsInRole("Admin"))) {
				return new OperationResult<string[]> { Unauthorized = true };
			}

			var userInfo = await _data.GetUserInformation(userId).NoSync();
			if (userInfo == null) {
				return new OperationResult<string[]> { NotFound = true };
			}

			return new OperationResult<string[]> { Result = userInfo.Roles.ToArray() };
		}

		public async ValueTask<OperationResult<string[]>> ReplaceUserRoles(ClaimsPrincipal user, long userId, string[] roles) {
			bool isAdmin = user.IsInRole("Admin");
			if (!(isAdmin || user.IsInRole("UserManagement"))) {
				return new OperationResult<string[]> { Unauthorized = true };
			}

			var userInfo = await _data.GetUserInformation(userId).NoSync();
			if (userInfo == null) {
				return new OperationResult<string[]> { NotFound = true };
			}

			foreach (var role in roles) {
				// only roles that the current user has
				if (!isAdmin && !user.IsInRole(role)) {
					return new OperationResult<string[]> { Unauthorized = true };
				}
			}

			await _data.ReplaceUserRoles(userId, roles).NoSync();

			return new OperationResult<string[]> { Result = roles.ToArray() };
		}

		public async ValueTask<OperationResult<string[]>> MergeUserRoles(ClaimsPrincipal user, long userId, string[] roles) {
			bool isAdmin = user.IsInRole("Admin");
			if (!(isAdmin || user.IsInRole("UserManagement"))) {
				return new OperationResult<string[]> { Unauthorized = true };
			}

			var userInfo = await _data.GetUserInformation(userId).NoSync();
			if (userInfo == null) {
				return new OperationResult<string[]> { NotFound = true };
			}

			HashSet<string> toAdd = new HashSet<string>();
			foreach (var role in roles) {
				// only roles that the current user has
				if (!isAdmin && !user.IsInRole(role)) {
					return new OperationResult<string[]> { Unauthorized = true };
				}
				if (!userInfo.Roles.Contains(role)) {
					toAdd.Add(role);
				}
			}

			if (toAdd.Count == 0) {
				return new OperationResult<string[]> { Result = userInfo.Roles.ToArray() };
			}

			await _data.AddUserRoles(userId, toAdd.ToArray()).NoSync();

			toAdd.AddRange(userInfo.Roles);
			return new OperationResult<string[]> { Result = toAdd.ToArray() };
		}

		public async ValueTask<OperationResult<string[]>> DeleteUserRoles(ClaimsPrincipal user, long userId, string[] roles) {
			bool isAdmin = user.IsInRole("Admin");
			if (!(isAdmin || user.IsInRole("UserManagement"))) {
				return new OperationResult<string[]> { Unauthorized = true };
			}

			var userInfo = await _data.GetUserInformation(userId).NoSync();
			if (userInfo == null) {
				return new OperationResult<string[]> { NotFound = true };
			}

			HashSet<string> toRemove = new HashSet<string>();
			foreach (var role in roles) {
				// only roles that the current user has
				if (!isAdmin && !user.IsInRole(role)) {
					return new OperationResult<string[]> { Unauthorized = true };
				}
				if (userInfo.Roles.Contains(role)) {
					toRemove.Add(role);
				}
			}

			if (toRemove.Count == 0) {
				return new OperationResult<string[]> { Result = userInfo.Roles.ToArray() };
			}

			await _data.RemoveUserRoles(userId, toRemove.ToArray()).NoSync();

			HashSet<string> remaining = new HashSet<string>(userInfo.Roles);
			foreach (var role in roles) {
				remaining.Remove(role);
			}
			return new OperationResult<string[]> { Result = remaining.ToArray() };
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

			var credentials = await _data.GetUserCredential("Windows", user.Identity.Name).NoSync();
			if (credentials == null) {
				return (false, null);
			}

			var userInfo = await _data.GetUserInformation(credentials.Value.usserId).NoSync();

			List<Claim> claims = new List<Claim>();
			claims.Add(new Claim(ClaimTypes.Name, userInfo.Name));
			foreach (var role in userInfo.Roles) {
				claims.Add(new Claim(ClaimTypes.Role, role));
			}

			return (true, GetTokenForUser(claims));
		}

		public async ValueTask<(bool success, string token)> AuthenticateBasic(string user, string password) {

			var credentials = await _data.GetUserCredential("Basic", user).NoSync();
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
				credentials = await _data.GetUserCredential("BasicPlainText", user).NoSync();
				if (!credentials.HasValue || !string.Equals(password, credentials.Value.value, StringComparison.Ordinal)) {
					return (false, null);
				}
			}

			var userInfo = await _data.GetUserInformation(credentials.Value.usserId).NoSync();
			if (userInfo == null) {
				return (false, null);
			}

			List<Claim> claims = new List<Claim>();
			claims.Add(new Claim(ClaimTypes.Name, userInfo.Name));
			foreach (var role in userInfo.Roles) {
				claims.Add(new Claim(ClaimTypes.Role, role));
			}

			return (true, GetTokenForUser(claims));
		}

		private string GetTokenForUser(List<Claim> claims) {
			using (var key = GetECDsa()) {
				var securityKey = new ECDsaSecurityKey(key);
				var tokenCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.EcdsaSha256);
				var token = new JwtSecurityToken("KeyVault", "urn:target", claims, expires: DateTime.UtcNow.AddHours(2), signingCredentials: tokenCredentials);
				return GetJwtTokenHandler().WriteToken(token);
			}
		}

		private sealed class BasicCredential {
			[JsonPropertyName("s")]
			public byte[] Salt { get; set; }
			[JsonPropertyName("p")]
			public byte[] Password { get; set; }
		}
	}
}
