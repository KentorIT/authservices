using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace Kentor.AuthServices.Internal
{
    internal static class CryptographyExtensions
    {
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
            using (var symmetricAlgorithm = SymmetricAlgorithm.Create())
            {
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
    }
}
