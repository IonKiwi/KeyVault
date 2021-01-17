using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace KeyVault.Extensions {
	public static class EnumerableExtensions {
		public static void AddRange<T>(this HashSet<T> set, IEnumerable<T> range) {
			foreach (var item in range) {
				set.Add(item);
			}
		}
	}
}
