using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace Kentor.AuthServices.Internal
{
    internal class RSAEncryptedXml : EncryptedXml
    {
        private readonly RSA privateKey;

        public RSAEncryptedXml(XmlDocument document, RSA rsaKey)
            : base(document)
        {
            privateKey = rsaKey;
        }

        // Try to decrypt the EncryptedKey by the given key
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "CipherReference"), System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "CipherData")]
        [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverageAttribute]
        public override byte[] DecryptEncryptedKey(EncryptedKey encryptedKey)
        {
            if (encryptedKey == null)
            {
                throw new ArgumentNullException(nameof(encryptedKey));
            }

            if (encryptedKey.CipherData.CipherValue == null)
            {
                throw new NotImplementedException("Unable to decode CipherData of type \"CipherReference\".");
            }

            // use the key info
            if (privateKey == null)
            {
                return base.DecryptEncryptedKey(encryptedKey);
            }

            var useOaep = (encryptedKey.EncryptionMethod != null &&
                         encryptedKey.EncryptionMethod.KeyAlgorithm == XmlEncRSAOAEPUrl);

            return DecryptKey(encryptedKey.CipherData.CipherValue, privateKey, useOaep);
        }

        //The following code comes from
        //http://referencesource.microsoft.com/#System.Configuration/System/Configuration/FipsAwareEncryptedXml.cs,fad55741da0e4b5f
        //and is included here because FipsAwareEncryptedXml class is private and only used by the framework when 
        //encrypting and decrypting application configuration files


        // Override EncryptedXml.GetDecryptionKey to avoid calling into CryptoConfig.CreateFromName
        // When detect AES, we need to return AesCryptoServiceProvider (FIPS certified) instead of AesManaged (FIPS obsolated)
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope")]
        [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverageAttribute]
        public override SymmetricAlgorithm GetDecryptionKey(EncryptedData encryptedData, string symmetricAlgorithmUri)
        {
            if (encryptedData == null)
            {
                throw new ArgumentNullException(nameof(encryptedData));
            }

            // If AES is used then assume FIPS is required
            bool fipsRequired = IsAesDetected(encryptedData, symmetricAlgorithmUri);

            if (fipsRequired)
            {
                // Obtain the EncryptedKey
                EncryptedKey ek = null;

                foreach (var ki in encryptedData.KeyInfo)
                {
                    KeyInfoEncryptedKey kiEncKey = ki as KeyInfoEncryptedKey;
                    if (kiEncKey != null)
                    {
                        ek = kiEncKey.EncryptedKey;
                        break;
                    }
                }

                // Got an EncryptedKey, decrypt it to get the AES key
                if (ek != null)
                {
                    byte[] key = DecryptEncryptedKey(ek);

                    // Construct FIPS-certified AES provider
                    if (key != null)
                    {
                        AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
                        aes.Key = key;

                        return aes;
                    }
                }
            }

            // Fallback to the base implementation
            return base.GetDecryptionKey(encryptedData, symmetricAlgorithmUri);
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Globalization", "CA1309:UseOrdinalStringComparison", MessageId = "System.String.Equals(System.String,System.String,System.StringComparison)")]
        [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverageAttribute]
        private static bool IsAesDetected(EncryptedData encryptedData, string symmetricAlgorithmUri)
        {
            if (encryptedData != null &&
                encryptedData.KeyInfo != null &&
                (symmetricAlgorithmUri != null || encryptedData.EncryptionMethod != null))
            {

                if (symmetricAlgorithmUri == null)
                {
                    symmetricAlgorithmUri = encryptedData.EncryptionMethod.KeyAlgorithm;
                }

                // Check if the Uri matches AES256
                return string.Equals(symmetricAlgorithmUri, EncryptedXml.XmlEncAES256Url, StringComparison.InvariantCultureIgnoreCase);
            }

            return false;
        }
    }
}
