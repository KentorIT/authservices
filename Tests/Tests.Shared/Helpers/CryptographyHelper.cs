using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using Sustainsys.Saml2.Internal;

namespace Sustainsys.Saml2.Tests.Helpers {
    internal static class CryptographyHelper {
        internal static void EncryptWithClause(this XmlElement elementToEncrypt, bool useOaep, X509Certificate2 certificate
            , string keyInfoClauseString, string keyName, string encryptionAlgorithm, bool generateKeyInfo, bool loadEncryptedMethod
            , bool loadEncryptedKey ,out EncryptedData encriptedDataOut) {
            if (certificate == null)
                throw new ArgumentNullException(nameof(certificate));
            string uriID = "#_12345";
            string[] args = new string[2] { keyName, uriID };

           var encryptedData = new EncryptedData
            {
                Type = EncryptedXml.XmlEncElementUrl,               
            };
			if (loadEncryptedMethod) {
                encryptedData.EncryptionMethod = new EncryptionMethod(encryptionAlgorithm);
            }

            var algorithm = useOaep ? EncryptedXml.XmlEncRSAOAEPUrl : EncryptedXml.XmlEncRSA15Url;
            var encryptedKey = new EncryptedKey()
            {
                EncryptionMethod = new EncryptionMethod(algorithm),
            };

            var encryptedXml = new EncryptedXml();
            byte[] encryptedElement;

            using (var symmetricAlgorithm = CryptographyExtensions.SymmetricFactory(encryptedKey.EncryptionMethod.KeyAlgorithm)) {
                symmetricAlgorithm.KeySize = 256;
                encryptedKey.CipherData = new CipherData(EncryptedXml.EncryptKey(symmetricAlgorithm.Key, (RSA)certificate.PublicKey.Key, useOaep));                
                encryptedElement = encryptedXml.EncryptData(elementToEncrypt, symmetricAlgorithm, false);               
            }
            encryptedData.CipherData.CipherValue = encryptedElement;
            if(generateKeyInfo) {
                encryptedData.KeyInfo = new KeyInfo();
                encryptedData.KeyInfo.AddClause(KeyInfoClauseFactory(keyInfoClauseString, encryptedKey, args));
                if(args[0]!= null) {
                    if (!loadEncryptedKey) {
                        args[0] = null;
                    }
                    encryptedKey.CarriedKeyName = args[0];
                    encryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(encryptedKey));                  
                }
                if(keyInfoClauseString == "KeyInfoRetrievalMethod") {
                    encryptedKey.Id = uriID.Substring(1);
                    encryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(encryptedKey));
                }
            }
            
            encriptedDataOut = encryptedData;
            EncryptedXml.ReplaceElement(elementToEncrypt, encryptedData, false);
        }

        private static KeyInfoClause KeyInfoClauseFactory(string keyInfoClauseString, EncryptedKey encryptedKey, string[] args) 
        {
            switch (keyInfoClauseString) {
                case "KeyInfoEncryptedKey":
                    return new KeyInfoEncryptedKey(encryptedKey);
                case "KeyInfoName":
                    return new KeyInfoName(args[0]);
                case "KeyInfoRetrievalMethod":
                    return new KeyInfoRetrievalMethod(args[1]);                  
                default:
                        throw new CryptographicException("No keyInfoClause string for factory");
            }
        }

    }
}
