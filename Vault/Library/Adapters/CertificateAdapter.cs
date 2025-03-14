// Copyright (c) Microsoft Corporation. All rights reserved. 
// Licensed under the MIT License. See License.txt in the project root for license information. 

using Azure.Security.KeyVault.Certificates;
using Microsoft.Azure.KeyVault.Models;
using System;
using System.Collections.Generic;

namespace Microsoft.Vault.Library.Adapters
{
    /// <summary>
    /// Adapter class to convert between old CertificateBundle and new KeyVaultCertificate models
    /// </summary>
    public static class CertificateAdapter
    {
        public static CertificateBundle ToCertificateBundle(this KeyVaultCertificateWithPolicy certificate)
        {
            if (certificate == null) return null;

            return new CertificateBundle
            {
                Id = certificate.Id.ToString(),
                Cer = certificate.Cer,
                ContentType = certificate.Properties.ContentType,
                Attributes = new CertificateAttributes
                {
                    Enabled = certificate.Properties.Enabled,
                    Created = certificate.Properties.CreatedOn,
                    Updated = certificate.Properties.UpdatedOn,
                    Expires = certificate.Properties.ExpiresOn,
                    NotBefore = certificate.Properties.NotBefore,
                    RecoveryLevel = certificate.Properties.RecoveryLevel
                },
                Tags = new Dictionary<string, string>(certificate.Properties.Tags ?? new Dictionary<string, string>()),
                Policy = certificate.Policy.ToCertificatePolicy()
            };
        }

        public static CertificateItem ToCertificateItem(this CertificateProperties properties)
        {
            if (properties == null) return null;

            return new CertificateItem
            {
                Id = properties.Id.ToString(),
                Attributes = new CertificateAttributes
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

        public static CertificateAttributes ToCertificateAttributes(this CertificateProperties properties)
        {
            if (properties == null) return null;

            return new CertificateAttributes
            {
                Enabled = properties.Enabled,
                Created = properties.CreatedOn,
                Updated = properties.UpdatedOn,
                Expires = properties.ExpiresOn,
                NotBefore = properties.NotBefore,
                RecoveryLevel = properties.RecoveryLevel
            };
        }

        public static Microsoft.Azure.KeyVault.Models.CertificatePolicy ToCertificatePolicy(this CertificatePolicy policy)
        {
            if (policy == null) return null;

            return new Microsoft.Azure.KeyVault.Models.CertificatePolicy
            {
                KeyProperties = new KeyProperties
                {
                    Exportable = policy.Exportable,
                    KeyType = policy.KeyType.ToString(),
                    KeySize = policy.KeySize,
                    ReuseKey = policy.ReuseKey
                },
                SecretProperties = new SecretProperties
                {
                    ContentType = policy.ContentType
                },
                X509CertificateProperties = new X509CertificateProperties
                {
                    Subject = policy.Subject,
                    SubjectAlternativeNames = policy.SubjectAlternativeNames?.ToX509SubjectAlternativeNames(),
                    ValidityInMonths = policy.ValidityInMonths,
                    Ekus = policy.EnhancedKeyUsage?.ToArray()
                },
                LifetimeActions = policy.LifetimeActions?.ToLifetimeActions(),
                IssuerParameters = new IssuerParameters
                {
                    Name = policy.IssuerName
                },
                Attributes = new CertificateAttributes
                {
                    Enabled = policy.Enabled
                }
            };
        }

        private static X509SubjectAlternativeNames ToX509SubjectAlternativeNames(this SubjectAlternativeNames sans)
        {
            if (sans == null) return null;

            return new X509SubjectAlternativeNames
            {
                DnsNames = sans.DnsNames?.ToArray(),
                Emails = sans.EmailAddresses?.ToArray(),
                UserPrincipalNames = sans.UserPrincipalNames?.ToArray()
            };
        }

        private static IList<LifetimeAction> ToLifetimeActions(this IEnumerable<LifetimeActionType> actions)
        {
            if (actions == null) return null;

            var result = new List<LifetimeAction>();
            foreach (var action in actions)
            {
                result.Add(new LifetimeAction
                {
                    Action = action.Action.ToString(),
                    TriggerType = action.TriggerType.ToString(),
                    TriggerValue = action.TriggerValue
                });
            }
            return result;
        }
    }
} 