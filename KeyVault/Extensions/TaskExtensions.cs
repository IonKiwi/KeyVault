using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace KeyVault.Extensions {
	public static class TaskExtensions {
		public static ConfiguredTaskAwaitable NoSync(this Task task) {
			return task.ConfigureAwait(false);
		}

		public static ConfiguredTaskAwaitable<T> NoSync<T>(this Task<T> task) {
			return task.ConfigureAwait(false);
		}

		public static ConfiguredValueTaskAwaitable NoSync(this ValueTask task) {
			return task.ConfigureAwait(false);
		}

		public static ConfiguredValueTaskAwaitable<T> NoSync<T>(this ValueTask<T> task) {
			return task.ConfigureAwait(false);
		}

		public static ConfiguredAsyncDisposable NoSync(this IAsyncDisposable task) {
			return task.ConfigureAwait(false);
		}

		public static ConfiguredCancelableAsyncEnumerable<T> NoSync<T>(this IAsyncEnumerable<T> task) {
			return task.ConfigureAwait(false);
		}
	}
}
