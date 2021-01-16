using KeyVault.Extensions;
using Microsoft.Data.Sqlite;
using System;
using System.Collections.Generic;
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

				using (var cmd = new SqliteCommand("CREATE TABLE [User] ([Id] INTEGER PRIMARY KEY AUTOINCREMENT, [Name] TEXT NOT NULL);", conn)) {
					await cmd.ExecuteNonQueryAsync().NoSync();
				}

				using (var cmd = new SqliteCommand("CREATE TABLE [UserRole] ([Id] INTEGER PRIMARY KEY AUTOINCREMENT, [UserId] INTEGER NOT NULL, [Role] TEXT NOT NULL, FOREIGN KEY (UserId) REFERENCES [User](Id) ON DELETE CASCADE ON UPDATE CASCADE);", conn)) {
					await cmd.ExecuteNonQueryAsync().NoSync();
				}

				using (var cmd = new SqliteCommand("CREATE TABLE [UserCredential] ([Id] INTEGER PRIMARY KEY AUTOINCREMENT, [UserId] INTEGER NOT NULL, [Type] TEXT NOT NULL, [Value] TEXT NOT NULL, FOREIGN KEY (UserId) REFERENCES [User](Id) ON DELETE CASCADE ON UPDATE CASCADE);", conn)) {
					await cmd.ExecuteNonQueryAsync().NoSync();
				}

				using (var cmd = new SqliteCommand("CREATE TABLE [Secret] ([Id] INTEGER PRIMARY KEY AUTOINCREMENT, [Name] TEXT NOT NULL, [Value] TEXT NOT NULL, [IV] BINARY NOT NULL);", conn)) {
					await cmd.ExecuteNonQueryAsync().NoSync();
				}

				using (var cmd = new SqliteCommand("CREATE TABLE [SecretAccess] ([SecretId] INTEGER NOT NULL, [UserId] INTEGER NOT NULL, [Access] TEXT NOT NULL, FOREIGN KEY (UserId) REFERENCES [User](Id) ON DELETE CASCADE ON UPDATE CASCADE, FOREIGN KEY (SecretId) REFERENCES [Secret](Id) ON DELETE CASCADE ON UPDATE CASCADE);", conn)) {
					await cmd.ExecuteNonQueryAsync().NoSync();
				}

				// INSERT INTO [User] ([Name]) Values ('admin')
				// INSERT INTO [UserCredential] ([UserId], [Type], [Value]) VALUES (1, 'BasicPlainText', 'admin')
				// INSERT INTO [UserCredential] ([UserId], [Type], [Value]) VALUES (1, 'Windows', 'domain\user')
			}
		}

		public async ValueTask<UserInformation> AuthenticateUser(string type, string value) {

			using (var conn = new SqliteConnection(_connectionString)) {
				await conn.OpenAsync().NoSync();

				using (var cmd = new SqliteCommand("SELECT [UserId] FROM [UserCredential] WHERE [Type] = @type AND [Value] = @value;", conn)) {
					cmd.Parameters.AddWithValue("@type", type);
					cmd.Parameters.AddWithValue("@value", value);
					object result = await cmd.ExecuteScalarAsync().NoSync();
					if (result is not long userId) {
						return null;
					}

					return await GetUserInformation(userId).NoSync();
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
				using (var cmd = new SqliteCommand("SELECT [Role] FROM [UserRole] WHERE [UserId] = @userId;", conn)) {
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
	}
}
