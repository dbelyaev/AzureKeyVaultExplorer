// Copyright (c) Microsoft Corporation. All rights reserved. 
// Licensed under the MIT License. See License.txt in the project root for license information. 

using Azure.Security.KeyVault.Keys;
using Microsoft.Azure.KeyVault.Models;
using System;
using System.Collections.Generic;

namespace Microsoft.Vault.Library.Adapters
{
    /// <summary>
    /// Adapter class to convert between old KeyBundle and new KeyVaultKey models
    /// </summary>
    public static class KeyAdapter
    {
        public static KeyBundle ToKeyBundle(this KeyVaultKey key)
        {
            if (key == null) return null;

            return new KeyBundle
            {
                Key = key.Key.ToJsonWebKey(),
                Attributes = new KeyAttributes
                {
                    Enabled = key.Properties.Enabled,
                    Created = key.Properties.CreatedOn,
                    Updated = key.Properties.UpdatedOn,
                    Expires = key.Properties.ExpiresOn,
                    NotBefore = key.Properties.NotBefore,
                    RecoveryLevel = key.Properties.RecoveryLevel
                },
                Tags = new Dictionary<string, string>(key.Properties.Tags ?? new Dictionary<string, string>())
            };
        }

        public static KeyItem ToKeyItem(this KeyProperties properties)
        {
            if (properties == null) return null;

            return new KeyItem
            {
                Kid = properties.Id.ToString(),
                Attributes = new KeyAttributes
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

        public static KeyAttributes ToKeyAttributes(this KeyProperties properties)
        {
            if (properties == null) return null;

            return new KeyAttributes
            {
                Enabled = properties.Enabled,
                Created = properties.CreatedOn,
                Updated = properties.UpdatedOn,
                Expires = properties.ExpiresOn,
                NotBefore = properties.NotBefore,
                RecoveryLevel = properties.RecoveryLevel
            };
        }

        public static JsonWebKey ToJsonWebKey(this Azure.Security.KeyVault.Keys.JsonWebKey key)
        {
            if (key == null) return null;

            return new JsonWebKey
            {
                Kty = key.KeyType.ToString(),
                Kid = key.Id.ToString(),
                N = key.N,
                E = key.E,
                D = key.D,
                DP = key.DP,
                DQ = key.DQ,
                QI = key.P,
                P = key.P,
                Q = key.Q,
                K = key.K,
                T = key.T,
                CRV = key.CurveName?.ToString(),
                X = key.X,
                Y = key.Y
            };
        }
    }
} 