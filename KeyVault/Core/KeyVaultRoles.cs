using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace KeyVault.Core {
	public static class KeyVaultRoles {
		public const string Admin = "Admin";
		//public const string ReadSecret = "ReadSecret";
		//public const string WriteSecret = "WriteSecret";
		public const string ListSecret = "ListSecret";
		public const string DeleteSecret = "DeleteSecret";
		public const string AssignUser = "AssignUser";
		public const string CreateUser = "CreateUser";
		public const string DeleteUser = "DeleteUser";
		public const string UpdateUser = "UpdateUser";
		public const string ListUser = "ListUser";
		public const string AddUserCredential = "AddUserCredential";
	}
}
