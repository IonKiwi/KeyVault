using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace KeyVault.Data {
	public sealed class UserInformation {
		public UserInformation(long id, string name, IReadOnlySet<string> roles) {
			Id = id;
			Name = name;
			Roles = roles;
		}

		public long Id { get; }
		public string Name { get; }
		public IReadOnlySet<String> Roles { get; }
	}
}
