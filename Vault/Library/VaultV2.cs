// Copyright (c) Microsoft Corporation. All rights reserved. 
// Licensed under the MIT License. See License.txt in the project root for license information. 

namespace Microsoft.Vault.Library
{
    using Azure.Core;
    using Azure.Identity;
    using Azure.Security.KeyVault.Secrets;
    using Azure.Security.KeyVault.Keys;
    using Azure.Security.KeyVault.Certificates;
    using System;
    using System.Collections.Generic;
    using System.Threading;
    using System.Threading.Tasks;
    using System.Security.Cryptography.X509Certificates;
    using Core;
    using System.Linq;

    /// <summary>
    /// Modern implementation of Vault class using Azure.Security.KeyVault.* SDKs
    /// For HA and DR story this supports up to two Azure Key Vaults, one in each region in the specified geo 
    /// </summary>
    public class VaultV2
    {
        private readonly SecretClient[] _secretClients;
        private readonly KeyClient[] _keyClients;
        private readonly CertificateClient[] _certificateClients;
        private readonly TokenCredential _credential;
        private bool Secondary => (_secretClients.Length == 2);

        public readonly string VaultsConfigFile;
        public readonly string[] VaultNames;
        public readonly VaultsConfig VaultsConfig;

        private static readonly Task CompletedTask = Task.FromResult(0);
        private static readonly object Lock = new object();

        /// <summary>
        /// UserPrincipalName of the currently authenticated user
        /// </summary>
        public string AuthenticatedUserName { get; private set; }

        /// <summary>
        /// Delegate to indicate progress
        /// </summary>
        /// <param name="position">Current position in the list of secrets, keys or certificates</param>
        public delegate void ListOperationProgressUpdate(int position);

        #region Constructors

        /// <summary>
        /// Creates the vault management instance based on provided Vaults Config dictionary
        /// </summary>
        public VaultV2(VaultsConfig vaultsConfig, VaultAccessTypeEnum accessType, params string[] vaultNames)
        {
            Guard.ArgumentNotNull(vaultsConfig, nameof(vaultsConfig));
            Guard.ArgumentCollectionNotEmpty(vaultNames, nameof(vaultNames));
            
            VaultsConfig = vaultsConfig;
            VaultNames = (from v in vaultNames where !string.IsNullOrEmpty(v) select v).ToArray();
            
            // Initialize clients based on vault names
            switch (VaultNames.Length)
            {
                case 1:
                    _credential = CreateTokenCredential(accessType, VaultNames[0]);
                    var vaultUri = new Uri($"https://{VaultNames[0]}.vault.azure.net/");
                    _secretClients = new[] { new SecretClient(vaultUri, _credential) };
                    _keyClients = new[] { new KeyClient(vaultUri, _credential) };
                    _certificateClients = new[] { new CertificateClient(vaultUri, _credential) };
                    break;
                case 2:
                    string primaryVaultName = VaultNames[0];
                    string secondaryVaultName = VaultNames[1];
                    
                    if (string.Equals(primaryVaultName, secondaryVaultName, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new ArgumentException($"Primary vault name {primaryVaultName} is equal to secondary vault name {secondaryVaultName}");
                    }

                    _credential = CreateTokenCredential(accessType, primaryVaultName);
                    var primaryUri = new Uri($"https://{primaryVaultName}.vault.azure.net/");
                    var secondaryUri = new Uri($"https://{secondaryVaultName}.vault.azure.net/");

                    _secretClients = new[]
                    {
                        new SecretClient(primaryUri, _credential),
                        new SecretClient(secondaryUri, _credential)
                    };

                    _keyClients = new[]
                    {
                        new KeyClient(primaryUri, _credential),
                        new KeyClient(secondaryUri, _credential)
                    };

                    _certificateClients = new[]
                    {
                        new CertificateClient(primaryUri, _credential),
                        new CertificateClient(secondaryUri, _credential)
                    };
                    break;
                default:
                    throw new ArgumentException($"Vault names length must be 1 or 2 only", nameof(VaultNames));
            }
        }

        /// <summary>
        /// Creates appropriate TokenCredential based on vault configuration
        /// </summary>
        private TokenCredential CreateTokenCredential(VaultAccessTypeEnum accessType, string vaultName)
        {
            Utils.GuardVaultName(vaultName);
            if (!VaultsConfig.ContainsKey(vaultName))
            {
                throw new KeyNotFoundException($"{vaultName} is not found in {VaultsConfigFile}");
            }

            VaultAccessType vat = VaultsConfig[vaultName];
            VaultAccess[] vas = (accessType == VaultAccessTypeEnum.ReadOnly) ? vat.ReadOnly : vat.ReadWrite;

            // Order possible VaultAccess options by Order property
            IEnumerable<VaultAccess> vaSorted = from va in vas orderby va.Order select va;

            // Try each credential type in order
            Queue<Exception> exceptions = new Queue<Exception>();
            string vaultAccessTypes = "";

            foreach (VaultAccess va in vaSorted)
            {
                try
                {
                    if (va is VaultAccessClientCertificate certAccess)
                    {
                        return new ClientCertificateCredential(
                            certAccess.TenantId,
                            certAccess.ClientId,
                            GetCertificate(certAccess.CertificateThumbprint));
                    }
                    else if (va is VaultAccessClientCredential credAccess)
                    {
                        return new ClientSecretCredential(
                            credAccess.TenantId,
                            credAccess.ClientId,
                            credAccess.ClientSecret);
                    }
                    else if (va is VaultAccessUserInteractive userAccess)
                    {
                        var options = new InteractiveBrowserCredentialOptions
                        {
                            TenantId = userAccess.TenantId,
                            ClientId = userAccess.ClientId,
                            RedirectUri = new Uri("http://localhost")
                        };
                        return new InteractiveBrowserCredential(options);
                    }
                }
                catch (Exception e)
                {
                    vaultAccessTypes += $" {va}";
                    exceptions.Enqueue(e);
                }
            }

            throw new VaultAccessException(
                $"Failed to get access to {vaultName} with all possible vault access type(s){vaultAccessTypes}",
                exceptions.ToArray());
        }

        private X509Certificate2 GetCertificate(string thumbprint)
        {
            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);
                var cert = store.Certificates.Find(
                    X509FindType.FindByThumbprint,
                    thumbprint,
                    false);
                
                if (cert.Count == 0)
                {
                    throw new InvalidOperationException($"Certificate with thumbprint {thumbprint} not found");
                }

                return cert[0];
            }
        }

        #endregion

        #region Secrets

        /// <summary>
        /// Gets specified secret by name from vault
        /// This function will prefer vault in the same region, in case we failed (including secret not found) it will fallback to other region
        /// </summary>
        public async Task<KeyVaultSecret> GetSecretAsync(string secretName, string secretVersion = null, CancellationToken cancellationToken = default)
        {
            Queue<Exception> exceptions = new Queue<Exception>();
            string vaults = "";

            foreach (var client in _secretClients)
            {
                try
                {
                    if (string.IsNullOrEmpty(secretVersion))
                    {
                        return await client.GetSecretAsync(secretName, cancellationToken: cancellationToken);
                    }
                    else
                    {
                        return await client.GetSecretVersionAsync(secretName, secretVersion, cancellationToken);
                    }
                }
                catch (Exception e)
                {
                    vaults += $" {client.VaultUri}";
                    exceptions.Enqueue(e);
                }
            }

            throw new SecretException($"Failed to get secret {secretName} from vault(s){vaults}", exceptions.ToArray());
        }

        /// <summary>
        /// Sets a secret in both vaults
        /// </summary>
        public async Task<KeyVaultSecret> SetSecretAsync(
            string secretName,
            string value,
            IDictionary<string, string> tags = null,
            string contentType = null,
            CancellationToken cancellationToken = default)
        {
            tags = Utils.AddMd5ChangedBy(tags, value, AuthenticatedUserName);
            
            var options = new SecretProperties
            {
                ContentType = contentType,
                Tags = tags
            };

            var t0 = _secretClients[0].SetSecretAsync(secretName, value, options, cancellationToken);
            var t1 = Secondary ? _secretClients[1].SetSecretAsync(secretName, value, options, cancellationToken) : CompletedTask;

            await Task.WhenAll(t0, t1);
            return await t0;
        }

        /// <summary>
        /// Lists all secrets in the vault
        /// </summary>
        public async Task<IEnumerable<SecretProperties>> ListSecretsAsync(
            int regionIndex = 0,
            ListOperationProgressUpdate progressUpdate = null,
            CancellationToken cancellationToken = default)
        {
            if (regionIndex >= _secretClients.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(regionIndex));
            }

            var results = new List<SecretProperties>();
            var client = _secretClients[regionIndex];
            
            await foreach (var page in client.GetPropertiesOfSecretsAsync(cancellationToken))
            {
                results.Add(page);
                progressUpdate?.Invoke(results.Count);
            }

            return results;
        }

        /// <summary>
        /// Gets all versions of a secret
        /// </summary>
        public async Task<IEnumerable<SecretProperties>> GetSecretVersionsAsync(
            string secretName,
            int regionIndex = 0,
            CancellationToken cancellationToken = default)
        {
            if (regionIndex >= _secretClients.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(regionIndex));
            }

            var results = new List<SecretProperties>();
            var client = _secretClients[regionIndex];

            await foreach (var version in client.GetPropertiesOfSecretVersionsAsync(secretName, cancellationToken))
            {
                results.Add(version);
            }

            return results;
        }

        /// <summary>
        /// Deletes a secret from both vaults
        /// </summary>
        public async Task<DeletedSecret> DeleteSecretAsync(string secretName, CancellationToken cancellationToken = default)
        {
            var t0 = _secretClients[0].StartDeleteSecretAsync(secretName, cancellationToken);
            var t1 = Secondary ? _secretClients[1].StartDeleteSecretAsync(secretName, cancellationToken) : CompletedTask;

            await Task.WhenAll(t0, t1);
            var operation = await t0;
            return await operation.WaitForCompletionAsync(cancellationToken);
        }

        #endregion
    }
} 