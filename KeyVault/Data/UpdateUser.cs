﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace KeyVault.Data {
	public class UpdateUser {
		[JsonPropertyName("name")]
		public string Name { get; set; }
	}
}
