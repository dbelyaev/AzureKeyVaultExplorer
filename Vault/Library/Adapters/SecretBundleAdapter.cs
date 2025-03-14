// Copyright (c) Microsoft Corporation. All rights reserved. 
// Licensed under the MIT License. See License.txt in the project root for license information. 

using Azure.Security.KeyVault.Secrets;
using Microsoft.Azure.KeyVault.Models;
using System;
using System.Collections.Generic;

namespace Microsoft.Vault.Library.Adapters
{
    /// <summary>
    /// Adapter class to convert between old SecretBundle and new KeyVaultSecret models
    /// </summary>
    public static class SecretBundleAdapter
    {
        public static SecretBundle ToSecretBundle(this KeyVaultSecret secret)
        {
            if (secret == null) return null;

            return new SecretBundle
            {
                Id = secret.Id.ToString(),
                Value = secret.Value,
                ContentType = secret.Properties.ContentType,
                Attributes = new SecretAttributes
                {
                    Enabled = secret.Properties.Enabled,
                    Created = secret.Properties.CreatedOn,
                    Updated = secret.Properties.UpdatedOn,
                    Expires = secret.Properties.ExpiresOn,
                    NotBefore = secret.Properties.NotBefore,
                    RecoveryLevel = secret.Properties.RecoveryLevel
                },
                Tags = new Dictionary<string, string>(secret.Properties.Tags ?? new Dictionary<string, string>())
            };
        }

        public static SecretItem ToSecretItem(this SecretProperties properties)
        {
            if (properties == null) return null;

            return new SecretItem
            {
                Id = properties.Id.ToString(),
                ContentType = properties.ContentType,
                Attributes = new SecretAttributes
                {
                    Enabled = properties.Enabled,
                    Created = properties.CreatedOn,
                    Updated = properties.UpdatedOn,
                    Expires = properties.ExpiresOn,
                    NotBefore = properties.NotBefore,
                    RecoveryLevel = properties.RecoveryLevel
                },
                Tags = new Dictionary<string, string>(properties.Tags ?? new Dictionary<string, string>())
            };
        }

        public static SecretAttributes ToSecretAttributes(this SecretProperties properties)
        {
            if (properties == null) return null;

            return new SecretAttributes
            {
                Enabled = properties.Enabled,
                Created = properties.CreatedOn,
                Updated = properties.UpdatedOn,
                Expires = properties.ExpiresOn,
                NotBefore = properties.NotBefore,
                RecoveryLevel = properties.RecoveryLevel
            };
        }
    }
} 