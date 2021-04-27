using Microsoft.IdentityModel.Tokens;
using Sustainsys.Saml2.Metadata;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using CipherData = System.Security.Cryptography.Xml.CipherData;
using EncryptedData = System.Security.Cryptography.Xml.EncryptedData;
using EncryptingCredentials = Microsoft.IdentityModel.Tokens.EncryptingCredentials;
using EncryptionMethod = System.Security.Cryptography.Xml.EncryptionMethod;
using SecurityAlgorithms = Microsoft.IdentityModel.Tokens.SecurityAlgorithms;

namespace Sustainsys.Saml2.Internal
{
    internal static class CryptographyExtensions
    {
        internal static void Encrypt(this XmlElement elementToEncrypt, EncryptingCredentials encryptingCredentials)
        {
            if (elementToEncrypt == null)
            {
                throw new ArgumentNullException(nameof(elementToEncrypt));
            }
            if (encryptingCredentials == null)
            {
                throw new ArgumentNullException(nameof(encryptingCredentials));
            }

            string enc;
            int keySize;
            switch (encryptingCredentials.Enc)
            {
                case SecurityAlgorithms.Aes128CbcHmacSha256:
                    enc = EncryptedXml.XmlEncAES128Url;
                    keySize = 128;
                    break;

                case SecurityAlgorithms.Aes192CbcHmacSha384:
                    enc = EncryptedXml.XmlEncAES192Url;
                    keySize = 192;
                    break;

                case SecurityAlgorithms.Aes256CbcHmacSha512:
                    enc = EncryptedXml.XmlEncAES256Url;
                    keySize = 256;
                    break;

                default:
                    throw new CryptographicException(
                        $"Unsupported cryptographic algorithm {encryptingCredentials.Enc}");
            }

            var encryptedData = new EncryptedData
            {
                Type = EncryptedXml.XmlEncElementUrl,
                EncryptionMethod = new EncryptionMethod(enc)
            };

            string alg;
            switch (encryptingCredentials.Alg)
            {
                case SecurityAlgorithms.RsaOAEP:
                    alg = EncryptedXml.XmlEncRSAOAEPUrl;
                    break;

                case SecurityAlgorithms.RsaPKCS1:
                    alg = EncryptedXml.XmlEncRSA15Url;
                    break;

                default:
                    throw new CryptographicException(
                        $"Unsupported cryptographic algorithm {encryptingCredentials.Alg}");
            }
            var encryptedKey = new EncryptedKey
            {
                EncryptionMethod = new EncryptionMethod(alg),
            };

            var encryptedXml = new EncryptedXml();
            byte[] encryptedElement;

            using (var symmetricAlgorithm = new AesCryptoServiceProvider()) {
                X509SecurityKey x509SecurityKey = encryptingCredentials.Key as X509SecurityKey;
                if (x509SecurityKey == null) {
                    throw new CryptographicException(
                        "The encrypting credentials have an unknown key of type {encryptingCredentials.Key.GetType()}");
                }

                symmetricAlgorithm.KeySize = keySize;
                encryptedKey.CipherData = new CipherData(EncryptedXml.EncryptKey(symmetricAlgorithm.Key,
                    (RSA)x509SecurityKey.PublicKey, alg == EncryptedXml.XmlEncRSAOAEPUrl));
                encryptedElement = encryptedXml.EncryptData(elementToEncrypt, symmetricAlgorithm, false);
            }
            encryptedData.CipherData.CipherValue = encryptedElement;

            encryptedData.KeyInfo = new KeyInfo();
            encryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(encryptedKey));
            EncryptedXml.ReplaceElement(elementToEncrypt, encryptedData, false);
        }

        internal static void Encrypt(this XmlElement elementToEncrypt, bool useOaep, X509Certificate2 certificate)
        {
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));

            var encryptedData = new EncryptedData
            {
                Type = EncryptedXml.XmlEncElementUrl,
                EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url)
            };

            var algorithm = useOaep ? EncryptedXml.XmlEncRSAOAEPUrl : EncryptedXml.XmlEncRSA15Url;
            var encryptedKey = new EncryptedKey
            {
                EncryptionMethod = new EncryptionMethod(algorithm),
            };

            var encryptedXml = new EncryptedXml();
            byte[] encryptedElement;

            using (var symmetricAlgorithm = new AesCryptoServiceProvider()) {
                symmetricAlgorithm.KeySize = 256;
                encryptedKey.CipherData = new CipherData(EncryptedXml.EncryptKey(symmetricAlgorithm.Key, (RSA)certificate.PublicKey.Key, useOaep));
                encryptedElement = encryptedXml.EncryptData(elementToEncrypt, symmetricAlgorithm, false);
            }
            encryptedData.CipherData.CipherValue = encryptedElement;

            encryptedData.KeyInfo = new KeyInfo();
            encryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(encryptedKey));
            EncryptedXml.ReplaceElement(elementToEncrypt, encryptedData, false);
        }

        internal static IEnumerable<XmlElement> Decrypt(this IEnumerable<XmlElement> elements, AsymmetricAlgorithm key)
        {
            foreach (var element in elements)
            {
                yield return element.Decrypt(key);
            }
        }

        internal static XmlElement Decrypt(this XmlElement element, AsymmetricAlgorithm key)
        {
            var xmlDoc = XmlHelpers.XmlDocumentFromString(element.OuterXml);

            var exml = new RSAEncryptedXml(xmlDoc, (RSA)key);

            exml.DecryptDocument();

            return xmlDoc.DocumentElement;
        }

        internal static RSACryptoServiceProvider GetSha256EnabledRSACryptoServiceProvider(
            this RSACryptoServiceProvider original)
        {
            // The provider is probably using the default ProviderType. That's
            // a problem, because it doesn't support SHA256. Let's do some
            // black magic and create a new provider of a type that supports
            // SHA256 without the user ever knowing we fix this. This is what
            // is done in X509AsymmetricKey.GetSignatureFormatter if
            // http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 isn't
            // a known algorithm, so users kind of expect this to be handled
            // for them magically.

            var cspParams = new CspParameters();
            cspParams.ProviderType = 24; //PROV_RSA_AES
            cspParams.KeyContainerName = original.CspKeyContainerInfo.KeyContainerName;
            cspParams.KeyNumber = (int)original.CspKeyContainerInfo.KeyNumber;
            SetMachineKeyFlag(original, cspParams);

            cspParams.Flags |= CspProviderFlags.UseExistingKey;

            return new RSACryptoServiceProvider(cspParams);
        }

        // We don't want to use Machine Key store during tests, so let's
        // put this one in an own method that's not included in coverage metrics.
        [ExcludeFromCodeCoverage]
        private static void SetMachineKeyFlag(RSACryptoServiceProvider provider, CspParameters cspParams)
        {
            if (provider.CspKeyContainerInfo.MachineKeyStore)
            {
                cspParams.Flags = CspProviderFlags.UseMachineKeyStore;
            }
        }

        // CryptoConfig.CreateFromName doesn't know about these
        private static Dictionary<string, Type> s_extraAlgorithms = new Dictionary<string, Type>(StringComparer.OrdinalIgnoreCase)
        {
            {  SecurityAlgorithms.RsaSha256Signature, typeof(ManagedRSASHA256SignatureDescription) },
            {  SecurityAlgorithms.RsaSha384Signature, typeof(ManagedRSASHA384SignatureDescription) },
            {  SecurityAlgorithms.RsaSha512Signature, typeof(ManagedRSASHA512SignatureDescription) }
        };

        public static object CreateAlgorithmFromName(string name, params object[] args)
        {
            var result = CryptoConfig.CreateFromName(name);
            if (result != null)
            {
                return result;
            }

            Type type;
            if (!s_extraAlgorithms.TryGetValue(name, out type))
            {
                throw new CryptographicException($"Unknown crypto algorithm '{name}'");
            }
            return Activator.CreateInstance(type, args);
        }

        internal static SymmetricAlgorithm SymmetricFactory(string type) {
            switch (type) {
                case EncryptedXml.XmlEncAES256Url:
                    return new AesCryptoServiceProvider();
                case EncryptedXml.XmlEncTripleDESUrl:
                    return new TripleDESCryptoServiceProvider();
                default:
                    return new AesCryptoServiceProvider();
            }
        }
    }
}