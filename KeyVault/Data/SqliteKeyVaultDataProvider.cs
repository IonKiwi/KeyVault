using KeyVault.Core;
using KeyVault.Extensions;
using KeyVault.Utilities;
using Microsoft.Data.Sqlite;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace KeyVault.Data {
	internal sealed class SqliteKeyVaultDataProvider : IKeyVaultDataProvider {

		private readonly string _connectionString;

		public SqliteKeyVaultDataProvider(string connectionString) {
			_connectionString = connectionString;
		}

		public async ValueTask Create() {
			using (var conn = new SqliteConnection(_connectionString)) {
				await conn.OpenAsync().NoSync();

				using (var cmd = new SqliteCommand("DROP TABLE IF EXISTS [SecretAccess];", conn)) {
					await cmd.ExecuteNonQueryAsync().NoSync();
				}

				using (var cmd = new SqliteCommand("DROP TABLE IF EXISTS [SecretData];", conn)) {
					await cmd.ExecuteNonQueryAsync().NoSync();
				}

				using (var cmd = new SqliteCommand("DROP TABLE IF EXISTS [Secret];", conn)) {
					await cmd.ExecuteNonQueryAsync().NoSync();
				}

				using (var cmd = new SqliteCommand("DROP TABLE IF EXISTS [UserCredential];", conn)) {
					await cmd.ExecuteNonQueryAsync().NoSync();
				}

				using (var cmd = new SqliteCommand("DROP TABLE IF EXISTS [UserRole];", conn)) {
					await cmd.ExecuteNonQueryAsync().NoSync();
				}

				using (var cmd = new SqliteCommand("DROP TABLE IF EXISTS [User];", conn)) {
					await cmd.ExecuteNonQueryAsync().NoSync();
				}

				using (var cmd = new SqliteCommand("CREATE TABLE [User] ([Id] INTEGER PRIMARY KEY AUTOINCREMENT, [Name] TEXT NOT NULL, UNIQUE([Name]) ON CONFLICT FAIL);", conn)) {
					await cmd.ExecuteNonQueryAsync().NoSync();
				}

				using (var cmd = new SqliteCommand("CREATE TABLE [UserRole] ([Id] INTEGER PRIMARY KEY AUTOINCREMENT, [UserId] INTEGER NOT NULL, [Role] TEXT NOT NULL, FOREIGN KEY ([UserId]) REFERENCES [User]([Id]) ON DELETE CASCADE ON UPDATE CASCADE);", conn)) {
					await cmd.ExecuteNonQueryAsync().NoSync();
				}

				using (var cmd = new SqliteCommand("CREATE INDEX [UserRole_UserId] ON [UserRole] ([UserId]);", conn)) {
					await cmd.ExecuteNonQueryAsync().NoSync();
				}

				using (var cmd = new SqliteCommand("CREATE TABLE [UserCredential] ([Id] INTEGER PRIMARY KEY AUTOINCREMENT, [UserId] INTEGER NOT NULL, [Type] TEXT NOT NULL, [Identifier] TEXT COLLATE NOCASE NOT NULL, [Value] TEXT NULL, FOREIGN KEY ([UserId]) REFERENCES [User]([Id]) ON DELETE CASCADE ON UPDATE CASCADE, UNIQUE([Type], [Identifier]) ON CONFLICT FAIL);", conn)) {
					await cmd.ExecuteNonQueryAsync().NoSync();
				}

				using (var cmd = new SqliteCommand("CREATE INDEX [UserCredential_UserId] ON [UserCredential] ([UserId]);", conn)) {
					await cmd.ExecuteNonQueryAsync().NoSync();
				}

				using (var cmd = new SqliteCommand("CREATE INDEX [UserCredential_TypeCredential] ON [UserCredential] ([Type], [Identifier]);", conn)) {
					await cmd.ExecuteNonQueryAsync().NoSync();
				}

				using (var cmd = new SqliteCommand("CREATE TABLE [Secret] ([Id] INTEGER PRIMARY KEY AUTOINCREMENT, [Name] TEXT NOT NULL, [Description] TEXT NULL, [CreateDate] DATETIME NOT NULL, [CreatorUserId] INTEGER NULL, [LastUpdateDate] DATETIME NULL, [LastUpdateUserId] INTEGER NULL, FOREIGN KEY ([CreatorUserId]) REFERENCES [User]([Id]) ON DELETE SET NULL ON UPDATE CASCADE, FOREIGN KEY ([LastUpdateUserId]) REFERENCES [User]([Id]) ON DELETE SET NULL ON UPDATE CASCADE, UNIQUE([Name]) ON CONFLICT FAIL);", conn)) {
					await cmd.ExecuteNonQueryAsync().NoSync();
				}

				using (var cmd = new SqliteCommand("CREATE UNIQUE INDEX [SECRET_UNIQUE_NAME] ON [Secret] ([Name]);", conn)) {
					await cmd.ExecuteNonQueryAsync().NoSync();
				}

				using (var cmd = new SqliteCommand("CREATE TABLE [SecretData] ([SecretId] INTEGER NOT NULL, [Name] TEXT NULL, [Description] TEXT NULL, [Type] TEXT NOT NULL, [Value] BINARY NOT NULL, [IV] BINARY NOT NULL, [CreateDate] DATETIME NOT NULL, [CreatorUserId] INTEGER NULL, [LastUpdateDate] DATETIME NULL, [LastUpdateUserId] INTEGER NULL, FOREIGN KEY ([SecretId]) REFERENCES [Secret]([Id]) ON DELETE CASCADE ON UPDATE CASCADE, FOREIGN KEY ([CreatorUserId]) REFERENCES [User]([Id]) ON DELETE SET NULL ON UPDATE CASCADE, FOREIGN KEY ([LastUpdateUserId]) REFERENCES [User]([Id]) ON DELETE SET NULL ON UPDATE CASCADE, UNIQUE([SecretId], [Name]) ON CONFLICT FAIL);", conn)) {
					await cmd.ExecuteNonQueryAsync().NoSync();
				}

				using (var cmd = new SqliteCommand("CREATE INDEX [SecretData_SecretIdName] ON [SecretData] ([SecretId], [Name]);", conn)) {
					await cmd.ExecuteNonQueryAsync().NoSync();
				}

				using (var cmd = new SqliteCommand("CREATE TABLE [SecretAccess] ([SecretId] INTEGER NOT NULL, [UserId] INTEGER NOT NULL, [Read] BOOLEAN NOT NULL, [Write] BOOLEAN NOT NULL, [Assign] BOOLEAN NOT NULL, FOREIGN KEY ([UserId]) REFERENCES [User]([Id]) ON DELETE CASCADE ON UPDATE CASCADE, FOREIGN KEY ([SecretId]) REFERENCES [Secret]([Id]) ON DELETE CASCADE ON UPDATE CASCADE, UNIQUE([SecretId], [UserId]) ON CONFLICT FAIL);", conn)) {
					await cmd.ExecuteNonQueryAsync().NoSync();
				}

				using (var cmd = new SqliteCommand("CREATE INDEX [SecretAccess_SecretId] ON [SecretAccess] ([SecretId]);", conn)) {
					await cmd.ExecuteNonQueryAsync().NoSync();
				}

				// admin user with plain text password [remove after first setup]

				using (var cmd = new SqliteCommand("INSERT INTO [User] ([Name]) Values ('admin');", conn)) {
					await cmd.ExecuteNonQueryAsync().NoSync();
				}

				using (var cmd = new SqliteCommand("INSERT INTO [UserCredential] ([UserId], [Type], [Identifier], [Value]) VALUES (1, 'BasicPlainText', 'admin', 'admin');", conn)) {
					await cmd.ExecuteNonQueryAsync().NoSync();
				}

				using (var cmd = new SqliteCommand("INSERT INTO [UserRole] ([UserId], [Role]) Values (1, 'Admin');", conn)) {
					await cmd.ExecuteNonQueryAsync().NoSync();
				}

				// INSERT INTO [UserCredential] ([UserId], [Type], [Identifier]) VALUES (1, 'Windows', 'domain\user')
			}
		}



		public async ValueTask<long> AddUser(NewUser user) {
			using (var conn = new SqliteConnection(_connectionString)) {
				await conn.OpenAsync().NoSync();

				using (var cmd = new SqliteCommand("INSERT INTO [User] ([Name]) Values (@name); SELECT last_insert_rowid();", conn)) {
					cmd.Parameters.AddWithValue("@name", user.Name);
					return (long)await cmd.ExecuteScalarAsync().NoSync();
				}
			}
		}

		public async ValueTask<bool> UpdateUser(long userId, NewUser newUser) {
			using (var conn = new SqliteConnection(_connectionString)) {
				await conn.OpenAsync().NoSync();

				using (var cmd = new SqliteCommand("UPDATE [User] SET [Name] = @name WHERE [Id] = @userId", conn)) {
					cmd.Parameters.AddWithValue("@userId", userId);
					cmd.Parameters.AddWithValue("@name", newUser.Name);
					return await cmd.ExecuteNonQueryAsync().NoSync() > 0;
				}
			}
		}

		public async ValueTask<bool> DeleteUser(long userId) {
			using (var conn = new SqliteConnection(_connectionString)) {
				await conn.OpenAsync().NoSync();

				using (var cmd = new SqliteCommand("DELETE FROM [User] WHERE [Id] = @userId;", conn)) {
					cmd.Parameters.AddWithValue("@userId", userId);
					return await cmd.ExecuteNonQueryAsync().NoSync() > 0;
				}
			}
		}

		public async ValueTask<UserInformation> GetUserInformation(long userId) {
			using (var conn = new SqliteConnection(_connectionString)) {
				await conn.OpenAsync().NoSync();

				string name;
				using (var cmd = new SqliteCommand("SELECT [Name] FROM [User] WHERE [Id] = @userId;", conn)) {
					cmd.Parameters.AddWithValue("@userId", userId);

					var reader = await cmd.ExecuteReaderAsync().NoSync();
					await using (reader.NoSync()) {

						if (!await reader.ReadAsync().NoSync()) {
							return null;
						}

						name = reader.GetString(0);
					}
				}

				var roles = new HashSet<string>();
				using (var cmd = new SqliteCommand("SELECT [Role] FROM [UserRole] WHERE [UserId] = @userId ORDER BY [Role] ASC;", conn)) {
					cmd.Parameters.AddWithValue("@userId", userId);

					var reader = await cmd.ExecuteReaderAsync().NoSync();
					await using (reader.NoSync()) {

						while (await reader.ReadAsync().NoSync()) {
							var role = reader.GetString(0);
							roles.Add(role);
						}
					}
				}

				return new UserInformation(userId, name, roles);
			}
		}

		public async ValueTask<List<UserInformation>> GetUsers() {
			using (var conn = new SqliteConnection(_connectionString)) {
				await conn.OpenAsync().NoSync();

				var result = new List<UserInformation>();
				var userRoles = new Dictionary<long, HashSet<string>>();

				using (var cmd = new SqliteCommand("SELECT [Id], [Name] FROM [User] ORDER BY [Id] ASC;", conn)) {

					var reader = await cmd.ExecuteReaderAsync().NoSync();
					await using (reader.NoSync()) {

						while (await reader.ReadAsync().NoSync()) {

							var userId = reader.GetInt64(0);
							var name = reader.GetString(1);
							var roles = new HashSet<string>();
							userRoles.Add(userId, roles);
							result.Add(new UserInformation(userId, name, roles));
						}
					}
				}

				foreach (var user in result) {
					using (var cmd2 = new SqliteCommand("SELECT [Role] FROM [UserRole] WHERE [UserId] = @userId ORDER BY [Role] ASC;", conn)) {
						cmd2.Parameters.AddWithValue("@userId", user.Id);

						var reader2 = await cmd2.ExecuteReaderAsync().NoSync();
						await using (reader2.NoSync()) {

							while (await reader2.ReadAsync().NoSync()) {
								var role = reader2.GetString(0);
								userRoles[user.Id].Add(role);
							}
						}
					}
				}

				return result;
			}
		}



		public async ValueTask<(long usserId, string value)?> GetUserCredential(string type, string identifier) {

			using (var conn = new SqliteConnection(_connectionString)) {
				await conn.OpenAsync().NoSync();

				using (var cmd = new SqliteCommand("SELECT [UserId], [Value] FROM [UserCredential] WHERE [Type] = @type AND [Identifier] = @identifier;", conn)) {
					cmd.Parameters.AddWithValue("@type", type);
					cmd.Parameters.AddWithValue("@identifier", identifier);
					var reader = await cmd.ExecuteReaderAsync().NoSync();
					await using (reader.NoSync()) {
						if (!await reader.ReadAsync().NoSync()) {
							return null;
						}

						long userId = reader.GetInt64(0);
						string value = null;
						if (!await reader.IsDBNullAsync(1).NoSync()) {
							value = reader.GetString(1);
						}
						return (userId, value);
					}
				}
			}
		}

		public async ValueTask<List<(long credentialId, string type, string identifier)>> GetUserCredentials(long userId) {

			using (var conn = new SqliteConnection(_connectionString)) {
				await conn.OpenAsync().NoSync();

				using (var cmd = new SqliteCommand("SELECT [Id], [Type], [Identifier] FROM [UserCredential] WHERE [UserId] = @userId ORDER BY [Id] ASC;", conn)) {
					cmd.Parameters.AddWithValue("@userId", userId);
					var reader = await cmd.ExecuteReaderAsync().NoSync();
					await using (reader.NoSync()) {
						var result = new List<(long credentialId, string type, string identifier)>();
						while (await reader.ReadAsync().NoSync()) {
							result.Add((reader.GetInt64(0), reader.GetString(1), reader.GetString(2)));
						}
						return result;
					}
				}
			}
		}

		public async ValueTask<bool> DeleteCredential(long credentialId) {

			using (var conn = new SqliteConnection(_connectionString)) {
				await conn.OpenAsync().NoSync();

				using (var cmd = new SqliteCommand("DELETE FROM [UserCredential] WHERE [Id] = @credentialId", conn)) {
					cmd.Parameters.AddWithValue("@credentialId", credentialId);
					return await cmd.ExecuteNonQueryAsync().NoSync() > 0;
				}
			}
		}

		public async ValueTask<long> AddCredential(long userId, string type, string identifier, string value) {

			using (var conn = new SqliteConnection(_connectionString)) {
				await conn.OpenAsync().NoSync();

				using (var cmd = new SqliteCommand("INSERT INTO [UserCredential] ([UserId], [Type], [Identifier], [Value]) VALUES (@userId, @type, @identifier, @value); SELECT last_insert_rowid();", conn)) {
					cmd.Parameters.AddWithValue("@userId", userId);
					cmd.Parameters.AddWithValue("@type", type);
					cmd.Parameters.AddWithValue("@identifier", identifier);
					cmd.Parameters.AddWithValue("@value", string.IsNullOrEmpty(value) ? DBNull.Value : value);
					return (long)await cmd.ExecuteScalarAsync().NoSync();
				}
			}
		}



		public async ValueTask ReplaceUserRoles(long userId, string[] roles) {

			using (var conn = new SqliteConnection(_connectionString)) {
				await conn.OpenAsync().NoSync();

				var transaction = (SqliteTransaction)await conn.BeginTransactionAsync().NoSync();
				await using (transaction.NoSync()) {

					using (var cmd = new SqliteCommand("DELETE FROM [UserRole] WHERE [UserId] = @userId;", conn, transaction)) {
						cmd.Parameters.AddWithValue("@userId", userId);
						await cmd.ExecuteNonQueryAsync().NoSync();
					}

					foreach (var role in roles) {
						using (var cmd = new SqliteCommand("INSERT INTO [UserRole] ([UserId], [Role]) VALUES (@userId, @role);", conn, transaction)) {
							cmd.Parameters.AddWithValue("@userId", userId);
							cmd.Parameters.AddWithValue("@role", role);
							await cmd.ExecuteNonQueryAsync().NoSync();
						}
					}

					await transaction.CommitAsync().NoSync();
				}
			}
		}

		public async ValueTask AddUserRoles(long userId, string[] roles) {

			using (var conn = new SqliteConnection(_connectionString)) {
				await conn.OpenAsync().NoSync();

				var transaction = (SqliteTransaction)await conn.BeginTransactionAsync().NoSync();
				await using (transaction.NoSync()) {

					foreach (var role in roles) {
						using (var cmd = new SqliteCommand("INSERT INTO [UserRole] ([UserId], [Role]) VALUES (@userId, @role);", conn, transaction)) {
							cmd.Parameters.AddWithValue("@userId", userId);
							cmd.Parameters.AddWithValue("@role", role);
							await cmd.ExecuteNonQueryAsync().NoSync();
						}
					}

					await transaction.CommitAsync().NoSync();
				}
			}
		}

		public async ValueTask<bool?> RemoveUserRoles(long userId, string[] roles) {

			using (var conn = new SqliteConnection(_connectionString)) {
				await conn.OpenAsync().NoSync();

				var transaction = (SqliteTransaction)await conn.BeginTransactionAsync().NoSync();
				await using (transaction.NoSync()) {

					bool allRemoved = true;
					bool allFailed = true;
					foreach (var role in roles) {
						using (var cmd = new SqliteCommand("DELETE FROM [UserRole] WHERE [UserId] = @userId AND [Role] = @role;", conn, transaction)) {
							cmd.Parameters.AddWithValue("@userId", userId);
							cmd.Parameters.AddWithValue("@role", role);
							int x = await cmd.ExecuteNonQueryAsync().NoSync();
							if (x == 0) {
								allRemoved = false;
							}
							else {
								allFailed = false;
							}
						}
					}

					await transaction.CommitAsync().NoSync();
					return allRemoved ? true : (allFailed ? false : null);
				}
			}
		}



		public async ValueTask<long> CreateSecret(long userId, string name, string description) {

			using (var conn = new SqliteConnection(_connectionString)) {
				await conn.OpenAsync().NoSync();

				var transaction = (SqliteTransaction)await conn.BeginTransactionAsync().NoSync();
				await using (transaction.NoSync()) {

					long secretId;
					using (var cmd = new SqliteCommand("INSERT INTO [Secret] ([Name], [Description], [CreateDate], [CreatorUserId]) VALUES (@name, @description, @createDate, @creatorUserId); SELECT last_insert_rowid();", conn, transaction)) {
						cmd.Parameters.AddWithValue("@name", name);
						cmd.Parameters.AddWithValue("@description", string.IsNullOrEmpty(description) ? DBNull.Value : description);
						cmd.Parameters.AddWithValue("@createDate", CommonUtility.GetTimestamp());
						cmd.Parameters.AddWithValue("@creatorUserId", userId);
						secretId = (long)await cmd.ExecuteScalarAsync().NoSync();
					}

					using (var cmd = new SqliteCommand("INSERT INTO [SecretAccess] ([SecretId], [UserId], [Read], [Write], [Assign]) VALUES (@secretId, @userId, @read, @write, @assign);", conn, transaction)) {
						cmd.Parameters.AddWithValue("@secretId", secretId);
						cmd.Parameters.AddWithValue("@userId", userId);
						cmd.Parameters.AddWithValue("@read", true);
						cmd.Parameters.AddWithValue("@write", true);
						cmd.Parameters.AddWithValue("@assign", true);
						await cmd.ExecuteNonQueryAsync().NoSync();
					}

					await transaction.CommitAsync().NoSync();
					return secretId;
				}
			}
		}

		public async ValueTask<long> UpdateSecretDescription(long userId, string name, string description) {

			using (var conn = new SqliteConnection(_connectionString)) {
				await conn.OpenAsync().NoSync();

				long secretId;
				using (var cmd = new SqliteCommand("UPDATE [Secret] SET [Description] = @description, [LastUpdateDate] = @lastUpdateData, [LastUpdateUserId] = @lastUpdateUserId WHERE [Name] = @name; SELECT [Id] FROM [Secret] WHERE [Name] = @name;", conn)) {
					cmd.Parameters.AddWithValue("@name", name);
					cmd.Parameters.AddWithValue("@description", description);
					cmd.Parameters.AddWithValue("@lastUpdateData", CommonUtility.GetTimestamp());
					cmd.Parameters.AddWithValue("@lastUpdateUserId", userId);
					secretId = (long)await cmd.ExecuteScalarAsync().NoSync();
					return secretId;
				}
			}
		}

		public async ValueTask<bool> DeleteSecret(long userId, string name) {
			using (var conn = new SqliteConnection(_connectionString)) {
				await conn.OpenAsync().NoSync();

				var result = new List<(long secretId, string name)>();
				using (var cmd = new SqliteCommand("DELETE FROM [Secret] WHERE [Name] = @name;", conn)) {
					cmd.Parameters.AddWithValue("@name", name);
					return await cmd.ExecuteNonQueryAsync().NoSync() > 0;
				}

			}
		}




		public async ValueTask<bool> AddSecretData(long userId, long secretId, string name, string description, KeyVaultSecretType type, byte[] value, byte[] iv) {

			using (var conn = new SqliteConnection(_connectionString)) {
				await conn.OpenAsync().NoSync();

				var transaction = (SqliteTransaction)await conn.BeginTransactionAsync().NoSync();
				await using (transaction.NoSync()) {

					var ts = CommonUtility.GetTimestamp();
					bool created;
					using (var cmd = new SqliteCommand("INSERT INTO [SecretData] ([SecretId], [Name], [Description], [Type], [Value], [IV], [CreateDate], [CreatorUserId]) VALUES (@secretId, @name, @description, @type, @value, @iv, @createDate, @creatorUserId);", conn, transaction)) {
						cmd.Parameters.AddWithValue("@secretId", secretId);
						cmd.Parameters.AddWithValue("@name", string.IsNullOrEmpty(name) ? DBNull.Value : name);
						cmd.Parameters.AddWithValue("@description", string.IsNullOrEmpty(description) ? DBNull.Value : description);
						cmd.Parameters.AddWithValue("@type", type.ToString());
						cmd.Parameters.AddWithValue("@value", value);
						cmd.Parameters.AddWithValue("@iv", iv);
						cmd.Parameters.AddWithValue("@createDate", ts);
						cmd.Parameters.AddWithValue("@creatorUserId", userId);
						created = await cmd.ExecuteNonQueryAsync().NoSync() > 0;
					}

					if (created) {
						using (var cmd = new SqliteCommand("UPDATE [Secret] SET [LastUpdateDate] = @lastUpdateData, [LastUpdateUserId] = @lastUpdateUserId WHERE [id] = @secretId;", conn, transaction)) {
							cmd.Parameters.AddWithValue("@secretId", secretId);
							cmd.Parameters.AddWithValue("@lastUpdateData", ts);
							cmd.Parameters.AddWithValue("@lastUpdateUserId", userId);
						}

						await transaction.CommitAsync().NoSync();
					}
					return created;
				}

			}
		}

		public async ValueTask<bool> UpdateSecretDataDescription(long userId, long secretId, string name, string description) {

			using (var conn = new SqliteConnection(_connectionString)) {
				await conn.OpenAsync().NoSync();

				var transaction = (SqliteTransaction)await conn.BeginTransactionAsync().NoSync();
				await using (transaction.NoSync()) {

					var ts = CommonUtility.GetTimestamp();
					bool updated;
					using (var cmd = new SqliteCommand("UPDATE [SecretData] SET [Description] = @description, [LastUpdateDate] = @lastUpdateData, [LastUpdateUserId] = @lastUpdateUserId WHERE [SecretId] = @secretId AND [Name] " + (string.IsNullOrEmpty(name) ? "IS NULL" : "= @name") + ";", conn, transaction)) {
						cmd.Parameters.AddWithValue("@secretId", secretId);
						if (!string.IsNullOrEmpty(name)) {
							cmd.Parameters.AddWithValue("@name", name);
						}
						cmd.Parameters.AddWithValue("@description", description);
						cmd.Parameters.AddWithValue("@lastUpdateData", ts);
						cmd.Parameters.AddWithValue("@lastUpdateUserId", userId);
						updated = await cmd.ExecuteNonQueryAsync().NoSync() > 0;
					}

					if (updated) {
						using (var cmd = new SqliteCommand("UPDATE [Secret] SET [LastUpdateDate] = @lastUpdateData, [LastUpdateUserId] = @lastUpdateUserId WHERE [id] = @secretId;", conn, transaction)) {
							cmd.Parameters.AddWithValue("@secretId", secretId);
							cmd.Parameters.AddWithValue("@lastUpdateData", ts);
							cmd.Parameters.AddWithValue("@lastUpdateUserId", userId);
						}

						await transaction.CommitAsync().NoSync();
					}
					return updated;
				}
			}
		}

		public async ValueTask<bool> UpdateSecretData(long userId, long secretId, string name, KeyVaultSecretType type, byte[] value, byte[] iv) {

			using (var conn = new SqliteConnection(_connectionString)) {
				await conn.OpenAsync().NoSync();

				var transaction = (SqliteTransaction)await conn.BeginTransactionAsync().NoSync();
				await using (transaction.NoSync()) {

					var ts = CommonUtility.GetTimestamp();
					bool updated;
					using (var cmd = new SqliteCommand("UPDATE [SecretData] SET [Type] = @type, [Value] = @value, [IV] = @iv, [LastUpdateDate] = @lastUpdateData, [LastUpdateUserId] = @lastUpdateUserId WHERE [SecretId] = @secretId AND [Name] " + (string.IsNullOrEmpty(name) ? "IS NULL" : "= @name") + ";", conn, transaction)) {
						cmd.Parameters.AddWithValue("@secretId", secretId);
						if (!string.IsNullOrEmpty(name)) {
							cmd.Parameters.AddWithValue("@name", name);
						}
						cmd.Parameters.AddWithValue("@type", type.ToString());
						cmd.Parameters.AddWithValue("@value", value);
						cmd.Parameters.AddWithValue("@iv", iv);
						cmd.Parameters.AddWithValue("@lastUpdateData", ts);
						cmd.Parameters.AddWithValue("@lastUpdateUserId", userId);
						updated = await cmd.ExecuteNonQueryAsync().NoSync() > 0;
					}

					if (updated) {
						using (var cmd = new SqliteCommand("UPDATE [Secret] SET [LastUpdateDate] = @lastUpdateData, [LastUpdateUserId] = @lastUpdateUserId WHERE [id] = @secretId;", conn, transaction)) {
							cmd.Parameters.AddWithValue("@secretId", secretId);
							cmd.Parameters.AddWithValue("@lastUpdateData", ts);
							cmd.Parameters.AddWithValue("@lastUpdateUserId", userId);
						}

						await transaction.CommitAsync().NoSync();
					}
					return updated;
				}
			}
		}

		public async ValueTask<bool> DeleteSecretData(long userId, long secretId, string name) {

			using (var conn = new SqliteConnection(_connectionString)) {
				await conn.OpenAsync().NoSync();

				var transaction = (SqliteTransaction)await conn.BeginTransactionAsync().NoSync();
				await using (transaction.NoSync()) {

					bool deleted = false;
					var result = new List<(long secretId, string name)>();
					using (var cmd = new SqliteCommand("DELETE FROM [SecretData] WHERE [SecretId] = @secretId AND [Name] " + (string.IsNullOrEmpty(name) ? "IS NULL" : "= @name") + ";", conn, transaction)) {
						cmd.Parameters.AddWithValue("@secretId", secretId);
						if (!string.IsNullOrEmpty(name)) {
							cmd.Parameters.AddWithValue("@name", name);
						}
						deleted = await cmd.ExecuteNonQueryAsync().NoSync() > 0;
					}

					if (deleted) {
						using (var cmd = new SqliteCommand("UPDATE [Secret] SET [LastUpdateDate] = @lastUpdateData, [LastUpdateUserId] = @lastUpdateUserId WHERE [id] = @secretId;", conn, transaction)) {
							cmd.Parameters.AddWithValue("@secretId", secretId);
							cmd.Parameters.AddWithValue("@lastUpdateData", CommonUtility.GetTimestamp());
							cmd.Parameters.AddWithValue("@lastUpdateUserId", userId);
						}

						await transaction.CommitAsync().NoSync();
					}
					return deleted;
				}

			}
		}

		public async ValueTask<List<(string name, string description, KeyVaultSecretType type, long creatorUserId, DateTime createdDate, long? lastUpdateUserId, DateTime? lastUpdateDate)>> GetSecretData(long secretId) {

			using (var conn = new SqliteConnection(_connectionString)) {
				await conn.OpenAsync().NoSync();

				var result = new List<(string name, string description, KeyVaultSecretType type, long creatorUserId, DateTime createdDate, long? lastUpdateUserId, DateTime? lastUpdateDate)>();
				using (var cmd = new SqliteCommand("SELECT [A].[Name], [A].[Description], [A].[Type], [A].[CreatorUserId], [A].[CreateDate], [A].[LastUpdateUserId], [A].[LastUpdateDate] FROM [SecretData] [A] WHERE [A].[SecretId] = @secretId ORDER BY [A].[Name] ASC;", conn)) {
					cmd.Parameters.AddWithValue("@secretId", secretId);

					var reader = await cmd.ExecuteReaderAsync().NoSync();
					await using (reader.NoSync()) {
						while (await reader.ReadAsync().NoSync()) {
							CommonUtility.TryParseEnum(reader.GetString(2), out KeyVaultSecretType secretType);
							result.Add((await GetNullableString(reader, 0).NoSync(), await GetNullableString(reader, 1).NoSync(), secretType, await GetNullableInt64(reader, 3).NoSync() ?? -1, CommonUtility.GetDateTimeFromTimestamp(reader.GetInt64(4)), await GetNullableInt64(reader, 5).NoSync(), FromNullableTimestamp(await GetNullableInt64(reader, 6).NoSync())));
						}
					}
				}

				return result;
			}
		}

		public async ValueTask<(KeyVaultSecretType type, byte[] value, byte[] iv)?> GetSecretData(long secretId, string name) {

			using (var conn = new SqliteConnection(_connectionString)) {
				await conn.OpenAsync().NoSync();

				using (var cmd = new SqliteCommand("SELECT [A].[Type], [A].[Value], [A].[IV] FROM [SecretData] [A] WHERE [A].[SecretId] = @secretId AND [A].[Name] " + (string.IsNullOrEmpty(name) ? "IS NULL" : "= @name") + ";", conn)) {
					cmd.Parameters.AddWithValue("@secretId", secretId);
					if (!string.IsNullOrEmpty(name)) {
						cmd.Parameters.AddWithValue("@name", name);
					}

					var reader = await cmd.ExecuteReaderAsync().NoSync();
					await using (reader.NoSync()) {
						if (!await reader.ReadAsync().NoSync()) {
							return null;
						}
						CommonUtility.TryParseEnum(reader.GetString(0), out KeyVaultSecretType secretType);
						return (secretType, GetBytes(reader, 1), GetBytes(reader, 2));
					}
				}

			}
		}



		public async ValueTask<KeyVaultSecret> GetSecret(string name) {

			using (var conn = new SqliteConnection(_connectionString)) {
				await conn.OpenAsync().NoSync();

				KeyVaultSecret result;
				Dictionary<long, KeyVaultSecretAccess> access = new Dictionary<long, KeyVaultSecretAccess>();
				Dictionary<string, KeyVaultSecretData> data = new Dictionary<string, KeyVaultSecretData>();
				using (var cmd = new SqliteCommand("SELECT [A].[Id], [A].[Name], [A].[Description], [A].[CreateDate], [A].[CreatorUserId], [A].[LastUpdateDate], [A].[LastUpdateUserId] FROM [Secret] [A] WHERE [A].[Name] = @name;", conn)) {
					cmd.Parameters.AddWithValue("@name", name);

					var reader = await cmd.ExecuteReaderAsync().NoSync();
					await using (reader.NoSync()) {
						if (!await reader.ReadAsync().NoSync()) {
							return null;
						}

						result = new KeyVaultSecret(reader.GetInt64(0), reader.GetString(1), await GetNullableString(reader, 2).NoSync(), CommonUtility.GetDateTimeFromTimestamp(reader.GetInt64(3)), await GetNullableInt64(reader, 4).NoSync() ?? -1, FromNullableTimestamp(await GetNullableInt64(reader, 5).NoSync()), await GetNullableInt64(reader, 6).NoSync(), data, access);
					}
				}

				using (var cmd = new SqliteCommand("SELECT [A].[UserId], [A].[Read], [A].[Write], [A].[Assign] FROM [SecretAccess] [A] WHERE [A].[SecretId] = @secretId ORDER BY [A].[UserId] ASC;", conn)) {
					cmd.Parameters.AddWithValue("@secretId", result.Id);

					var reader = await cmd.ExecuteReaderAsync().NoSync();
					await using (reader.NoSync()) {
						while (await reader.ReadAsync().NoSync()) {
							var a = new KeyVaultSecretAccess(result, reader.GetInt64(0), reader.GetBoolean(1), reader.GetBoolean(2), reader.GetBoolean(3));
							access.Add(a.UserId, a);
						}
					}
				}

				using (var cmd = new SqliteCommand("SELECT [A].[Name], [A].[Description], [A].[Type], [A].[CreateDate], [A].[CreatorUserId], [A].[LastUpdateDate], [A].[LastUpdateUserId] FROM [SecretData] [A] WHERE [A].[SecretId] = @secretId ORDER BY [A].[Name] ASC;", conn)) {
					cmd.Parameters.AddWithValue("@secretId", result.Id);

					var reader = await cmd.ExecuteReaderAsync().NoSync();
					await using (reader.NoSync()) {
						while (await reader.ReadAsync().NoSync()) {
							CommonUtility.TryParseEnum(reader.GetString(2), out KeyVaultSecretType secretType);
							var a = new KeyVaultSecretData(result, await GetNullableString(reader, 0).NoSync(), await GetNullableString(reader, 1).NoSync(), secretType, CommonUtility.GetDateTimeFromTimestamp(reader.GetInt64(3)), await GetNullableInt64(reader, 4).NoSync() ?? -1, FromNullableTimestamp(await GetNullableInt64(reader, 5).NoSync()), await GetNullableInt64(reader, 6).NoSync());
							data.Add(a.Name ?? string.Empty, a);
						}
					}
				}

				return result;
			}
		}

		public async ValueTask<List<(long secretId, string name, string description, long creatorUserId, DateTime createdDate, long? lastUpdateUserId, DateTime? lastUpdateDate)>> GetSecrets() {

			using (var conn = new SqliteConnection(_connectionString)) {
				await conn.OpenAsync().NoSync();

				var result = new List<(long secretId, string name, string description, long creatorUserId, DateTime createdDate, long? lastUpdateUserId, DateTime? lastUpdateDate)>();
				using (var cmd = new SqliteCommand("SELECT [A].[Id], [A].[Name], [A].[Description], [A].[CreatorUserId], [A].[CreateDate], [A].[LastUpdateUserId], [A].[LastUpdateDate] FROM [Secret] [A] ORDER BY [A].[Id] ASC;", conn)) {
					var reader = await cmd.ExecuteReaderAsync().NoSync();
					await using (reader.NoSync()) {
						while (await reader.ReadAsync().NoSync()) {
							result.Add((reader.GetInt64(0), reader.GetString(1), await GetNullableString(reader, 2).NoSync(), await GetNullableInt64(reader, 3).NoSync() ?? -1, CommonUtility.GetDateTimeFromTimestamp(reader.GetInt64(4)), await GetNullableInt64(reader, 5).NoSync(), FromNullableTimestamp(await GetNullableInt64(reader, 6).NoSync())));
						}
					}
				}

				return result;
			}
		}

		public async ValueTask<List<(long secretId, string name, string description, long creatorUserId, DateTime createdDate, long? lastUpdateUserId, DateTime? lastUpdateDate)>> GetSecrets(long userId) {

			using (var conn = new SqliteConnection(_connectionString)) {
				await conn.OpenAsync().NoSync();

				var result = new List<(long secretId, string name, string description, long creatorUserId, DateTime createdDate, long? lastUpdateUserId, DateTime? lastUpdateDate)>();
				using (var cmd = new SqliteCommand("SELECT [A].[Id], [A].[Name], [A].[Description], [A].[CreatorUserId], [A].[CreateDate], [A].[LastUpdateUserId], [A].[LastUpdateDate] FROM [Secret] [A] WHERE [A].[Id] IN (SELECT DISTINCT [B].[SecretId] FROM [SecretAccess] [B] WHERE [B].[UserId] = @userId AND ([B].[Read] = 1 OR [B].[Write] = 1 OR [B].[Assign] = 1)) ORDER BY [A].[Id] ASC;", conn)) {
					cmd.Parameters.AddWithValue("@userId", userId);

					var reader = await cmd.ExecuteReaderAsync().NoSync();
					await using (reader.NoSync()) {
						while (await reader.ReadAsync().NoSync()) {
							result.Add((reader.GetInt64(0), reader.GetString(1), await GetNullableString(reader, 2).NoSync(), await GetNullableInt64(reader, 3).NoSync() ?? -1, CommonUtility.GetDateTimeFromTimestamp(reader.GetInt64(4)), await GetNullableInt64(reader, 5).NoSync(), FromNullableTimestamp(await GetNullableInt64(reader, 6).NoSync())));
						}
					}
				}

				return result;
			}
		}



		public async ValueTask<bool> DeleteSecretsWithNoAccess() {

			using (var conn = new SqliteConnection(_connectionString)) {
				await conn.OpenAsync().NoSync();

				var result = new List<(long secretId, string name)>();
				using (var cmd = new SqliteCommand("DELETE FROM [Secret] WHERE [Id] NOT IN (SELECT DISTINCT [B].[SecretId] FROM [SecretAccess] [B]);", conn)) {
					return await cmd.ExecuteNonQueryAsync().NoSync() > 0;
				}

			}
		}

		public async ValueTask<List<(long secretId, string name, string description, long creatorUserId, DateTime createdDate, long? lastUpdateUserId, DateTime? lastUpdateDate)>> GetSecretsWithNoAccess() {

			using (var conn = new SqliteConnection(_connectionString)) {
				await conn.OpenAsync().NoSync();

				var result = new List<(long secretId, string name, string description, long creatorUserId, DateTime createdDate, long? lastUpdateUserId, DateTime? lastUpdateDate)>();
				using (var cmd = new SqliteCommand("SELECT [A].[Id], [A].[Name], [A].[Description], [A].[CreatorUserId], [A].[CreateDate], [A].[LastUpdateUserId], [A].[LastUpdateDate] FROM [Secret] [A] LEFT OUTER JOIN [SecretAccess] [B] ON [A].[Id] = [B].[SecretId] WHERE [B].[SecretId] IS NULL ORDER BY [A].[Id] ASC;", conn)) {
					var reader = await cmd.ExecuteReaderAsync().NoSync();
					await using (reader.NoSync()) {
						while (await reader.ReadAsync().NoSync()) {
							result.Add((reader.GetInt64(0), reader.GetString(1), await GetNullableString(reader, 2).NoSync(), await GetNullableInt64(reader, 3).NoSync() ?? -1, CommonUtility.GetDateTimeFromTimestamp(reader.GetInt64(4)), await GetNullableInt64(reader, 5).NoSync(), FromNullableTimestamp(await GetNullableInt64(reader, 6).NoSync())));
						}
					}
				}

				return result;
			}
		}



		public async ValueTask<bool> DeleteSecretAccess(long secretId, long userId) {

			using (var conn = new SqliteConnection(_connectionString)) {
				await conn.OpenAsync().NoSync();

				using (var cmd = new SqliteCommand("DELETE FROM [SecretAccess] WHERE [SecretId] = @secretId AND [UserId] = @userId", conn)) {
					cmd.Parameters.AddWithValue("@secretId", secretId);
					cmd.Parameters.AddWithValue("@userId", userId);
					return await cmd.ExecuteNonQueryAsync().NoSync() > 0;
				}
			}
		}

		public async ValueTask<bool> AddSecretAccess(long secretId, long userId, bool read, bool write, bool assign) {

			using (var conn = new SqliteConnection(_connectionString)) {
				await conn.OpenAsync().NoSync();

				using (var cmd = new SqliteCommand("INSERT INTO [SecretAccess] ([SecretId], [UserId], [Read], [Write], [Assign]) VALUES (@secretId, @userId, @read, @write, @assign);", conn)) {
					cmd.Parameters.AddWithValue("@secretId", secretId);
					cmd.Parameters.AddWithValue("@userId", userId);
					cmd.Parameters.AddWithValue("@read", read);
					cmd.Parameters.AddWithValue("@write", write);
					cmd.Parameters.AddWithValue("@assign", assign);
					return await cmd.ExecuteNonQueryAsync().NoSync() > 0;
				}
			}
		}

		public async ValueTask<bool> AddOrUpdateSecretAccess(long secretId, long userId, bool read, bool write, bool assign) {

			using (var conn = new SqliteConnection(_connectionString)) {
				await conn.OpenAsync().NoSync();

				using (var cmd = new SqliteCommand("INSERT INTO [SecretAccess] ([SecretId], [UserId], [Read], [Write], [Assign]) VALUES (@secretId, @userId, @read, @write, @assign) ON CONFLICT([SecretId], [UserId]) DO UPDATE SET [Read] = @read, [Write] = @write, [Assign] = @assign;", conn)) {
					cmd.Parameters.AddWithValue("@secretId", secretId);
					cmd.Parameters.AddWithValue("@userId", userId);
					cmd.Parameters.AddWithValue("@read", read);
					cmd.Parameters.AddWithValue("@write", write);
					cmd.Parameters.AddWithValue("@assign", assign);
					return await cmd.ExecuteNonQueryAsync().NoSync() > 0;
				}
			}
		}



		private static byte[] GetBytes(SqliteDataReader reader, int ordinal) {
			using (var s = reader.GetStream(ordinal)) {
				if (s is MemoryStream ms) {
					return ms.ToArray();
				}
				using (var s2 = new MemoryStream()) {
					s.CopyTo(s2);
					return s2.ToArray();
				}
			}
		}

		private static async Task<long?> GetNullableInt64(SqliteDataReader reader, int ordinal) {
			if (await reader.IsDBNullAsync(ordinal).NoSync()) {
				return null;
			}
			return reader.GetInt64(ordinal);
		}

		private static async Task<string> GetNullableString(SqliteDataReader reader, int ordinal) {
			if (await reader.IsDBNullAsync(ordinal).NoSync()) {
				return null;
			}
			return reader.GetString(ordinal);
		}

		private static DateTime? FromNullableTimestamp(long? timestamp) {
			if (!timestamp.HasValue) {
				return null;
			}
			return CommonUtility.GetDateTimeFromTimestamp(timestamp.Value);
		}
	}
}
