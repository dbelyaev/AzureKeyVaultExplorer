// Copyright (c) Microsoft Corporation. All rights reserved. 
// Licensed under the MIT License. See License.txt in the project root for license information. 

using Microsoft.Azure.KeyVault.Models;
using Microsoft.Vault.Library.Adapters;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.Vault.Library
{
    /// <summary>
    /// Wrapper class that implements the old interface using the new VaultV2 implementation
    /// This class helps with the transition from the old to the new Azure SDK
    /// </summary>
    public class VaultWrapper
    {
        private readonly VaultV2 _vaultV2;

        public VaultWrapper(VaultsConfig vaultsConfig, VaultAccessTypeEnum accessType, params string[] vaultNames)
        {
            _vaultV2 = new VaultV2(vaultsConfig, accessType, vaultNames);
        }

        #region Secrets

        public async Task<SecretBundle> GetSecretAsync(string secretName, string secretVersion = null, CancellationToken cancellationToken = default)
        {
            var secret = await _vaultV2.GetSecretAsync(secretName, secretVersion, cancellationToken);
            return secret.ToSecretBundle();
        }

        public async Task<SecretBundle> SetSecretAsync(
            string secretName,
            string value,
            Dictionary<string, string> tags = null,
            string contentType = null,
            SecretAttributes secretAttributes = null,
            CancellationToken cancellationToken = default)
        {
            var secret = await _vaultV2.SetSecretAsync(secretName, value, tags, contentType, cancellationToken);
            return secret.ToSecretBundle();
        }

        public async Task<IList<SecretItem>> ListSecretsAsync(
            int regionIndex = 0,
            Vault.ListOperationProgressUpdate progressUpdate = null,
            CancellationToken cancellationToken = default)
        {
            var secrets = await _vaultV2.ListSecretsAsync(
                regionIndex,
                progressUpdate == null ? null : (pos) => progressUpdate(pos),
                cancellationToken);
            return secrets.Select(s => s.ToSecretItem()).ToList();
        }

        public async Task<IList<SecretItem>> GetSecretVersionsAsync(
            string secretName,
            int regionIndex = 0,
            CancellationToken cancellationToken = default)
        {
            var versions = await _vaultV2.GetSecretVersionsAsync(secretName, regionIndex, cancellationToken);
            return versions.Select(v => v.ToSecretItem()).ToList();
        }

        public async Task<DeletedSecretBundle> DeleteSecretAsync(string secretName, CancellationToken cancellationToken = default)
        {
            var deleted = await _vaultV2.DeleteSecretAsync(secretName, cancellationToken);
            return new DeletedSecretBundle
            {
                Id = deleted.Id.ToString(),
                Value = deleted.Value,
                ContentType = deleted.Properties.ContentType,
                Attributes = deleted.Properties.ToSecretAttributes(),
                Tags = new Dictionary<string, string>(deleted.Properties.Tags ?? new Dictionary<string, string>()),
                DeletedDate = deleted.DeletedOn,
                ScheduledPurgeDate = deleted.ScheduledPurgeDate,
                RecoveryId = deleted.RecoveryId
            };
        }

        #endregion

        #region Keys

        public async Task<KeyBundle> GetKeyAsync(string keyName, string keyVersion = null, CancellationToken cancellationToken = default)
        {
            var key = await _vaultV2.GetKeyAsync(keyName, keyVersion, cancellationToken);
            return key.ToKeyBundle();
        }

        public async Task<IList<KeyItem>> ListKeysAsync(
            int regionIndex = 0,
            Vault.ListOperationProgressUpdate progressUpdate = null,
            CancellationToken cancellationToken = default)
        {
            var keys = await _vaultV2.ListKeysAsync(
                regionIndex,
                progressUpdate == null ? null : (pos) => progressUpdate(pos),
                cancellationToken);
            return keys.Select(k => k.ToKeyItem()).ToList();
        }

        public async Task<IList<KeyItem>> GetKeyVersionsAsync(
            string keyName,
            int regionIndex = 0,
            CancellationToken cancellationToken = default)
        {
            var versions = await _vaultV2.GetKeyVersionsAsync(keyName, regionIndex, cancellationToken);
            return versions.Select(v => v.ToKeyItem()).ToList();
        }

        public async Task<DeletedKeyBundle> DeleteKeyAsync(string keyName, CancellationToken cancellationToken = default)
        {
            var deleted = await _vaultV2.DeleteKeyAsync(keyName, cancellationToken);
            return new DeletedKeyBundle
            {
                Key = deleted.Key.ToJsonWebKey(),
                Attributes = deleted.Properties.ToKeyAttributes(),
                Tags = new Dictionary<string, string>(deleted.Properties.Tags ?? new Dictionary<string, string>()),
                DeletedDate = deleted.DeletedOn,
                ScheduledPurgeDate = deleted.ScheduledPurgeDate,
                RecoveryId = deleted.RecoveryId
            };
        }

        #endregion

        #region Certificates

        public async Task<CertificateBundle> GetCertificateAsync(
            string certificateName,
            string certificateVersion = null,
            CancellationToken cancellationToken = default)
        {
            var certificate = await _vaultV2.GetCertificateAsync(certificateName, certificateVersion, cancellationToken);
            return certificate.ToCertificateBundle();
        }

        public async Task<IList<CertificateItem>> ListCertificatesAsync(
            int regionIndex = 0,
            Vault.ListOperationProgressUpdate progressUpdate = null,
            CancellationToken cancellationToken = default)
        {
            var certificates = await _vaultV2.ListCertificatesAsync(
                regionIndex,
                progressUpdate == null ? null : (pos) => progressUpdate(pos),
                cancellationToken);
            return certificates.Select(c => c.ToCertificateItem()).ToList();
        }

        public async Task<IList<CertificateItem>> GetCertificateVersionsAsync(
            string certificateName,
            int regionIndex = 0,
            CancellationToken cancellationToken = default)
        {
            var versions = await _vaultV2.GetCertificateVersionsAsync(certificateName, regionIndex, cancellationToken);
            return versions.Select(v => v.ToCertificateItem()).ToList();
        }

        public async Task<DeletedCertificateBundle> DeleteCertificateAsync(
            string certificateName,
            CancellationToken cancellationToken = default)
        {
            var deleted = await _vaultV2.DeleteCertificateAsync(certificateName, cancellationToken);
            return new DeletedCertificateBundle
            {
                Id = deleted.Id.ToString(),
                Cer = deleted.Cer,
                ContentType = deleted.Properties.ContentType,
                Attributes = deleted.Properties.ToCertificateAttributes(),
                Tags = new Dictionary<string, string>(deleted.Properties.Tags ?? new Dictionary<string, string>()),
                DeletedDate = deleted.DeletedOn,
                ScheduledPurgeDate = deleted.ScheduledPurgeDate,
                RecoveryId = deleted.RecoveryId
            };
        }

        #endregion
    }
} 