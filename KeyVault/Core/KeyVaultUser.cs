using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace KeyVault.Core {
	public sealed class KeyVaultUser {

		private string[] _roles;

		public KeyVaultUser(string id, string name, string[] roles) {
			Id = id;
			Name = name;
			_roles = roles;
		}

		public string Id { get; }

		public string Name { get; }

		public bool HasRole(string role) => _roles.Contains(role);
	}
}
