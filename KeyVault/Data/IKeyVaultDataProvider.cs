using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace KeyVault.Data {
	public interface IKeyVaultDataProvider {
		ValueTask Create();

		ValueTask<UserInformation> GetUserInformation(long userId);
		ValueTask<UserInformation> AuthenticateUser(string type, string value);
	}
}
