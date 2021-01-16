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
			}
		}
	}
}
