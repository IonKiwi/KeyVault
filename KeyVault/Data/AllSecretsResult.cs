﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace KeyVault.Data {
	public class AllSecretsResult {
		[JsonPropertyName("secrets")]
		public List<SecretData> Secrets { get; set; }
	}
}
