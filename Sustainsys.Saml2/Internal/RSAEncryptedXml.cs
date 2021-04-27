using Sustainsys.Saml2.Configuration;
using System;
using System.Collections;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace Sustainsys.Saml2.Internal
{
    internal class RSAEncryptedXml : EncryptedXml
    {
        private readonly RSA privateKey;
        private XmlDocument document;
        private string symmetricAlgorithmUri;

        public RSAEncryptedXml(XmlDocument document, RSA rsaKey)
            : base(document) {
            this.document = document;
            privateKey = rsaKey;
        }

        // Try to decrypt the EncryptedKey by the given key
        public override byte[] DecryptEncryptedKey(EncryptedKey encryptedKey)
        {
            if (encryptedKey == null)
            {
                throw new ArgumentNullException(nameof(encryptedKey));
            }

            if (encryptedKey.CipherData.CipherValue == null || encryptedKey.CipherData.CipherValue.Count() == 0)
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

        // Override EncryptedXml.GetDecryptionKey to avoid calling into CryptoConfig.CreateFromName
        // When detect AES, we need to return AesCryptoServiceProvider (FIPS certified) instead of AesManaged (FIPS obsolated)
        public override SymmetricAlgorithm GetDecryptionKey(EncryptedData encryptedData, string symmetricAlgorithmUri) {
            if (encryptedData == null) {
                throw new ArgumentNullException("No Encrypted Data Provided");
            }
            // If the Uri is not provided by the application, try to get it from the EncryptionMethod
            if (symmetricAlgorithmUri == null) {
                if (encryptedData.EncryptionMethod == null) {
                    throw new CryptographicException("No Cryptograpy algorithm provided in encryption method");
                }
                this.symmetricAlgorithmUri = encryptedData.EncryptionMethod.KeyAlgorithm;
			} else {
                this.symmetricAlgorithmUri = symmetricAlgorithmUri;
            }
            // If AES is used then assume FIPS is required
            if (IsSymmetricKeyRequiresFipsCompliantImplementation(this.symmetricAlgorithmUri)) {
                if (encryptedData.KeyInfo == null) {
                    return null;
                }

                EncryptedKey ek = GetEncryptedKeyfromKeyInfoClause(encryptedData);
                // if we have an EncryptedKey, decrypt to get the symmetric key
                if (ek != null) {
                    // now process the EncryptedKey, loop recursively           
                    byte[] key = DecryptEncryptedKey(ek);
                    if (key == null) {
                        throw new CryptographicException("No Decryption Key found");
                    }
                    // encryptedData.EncryptionMethod.KeyAlgorithm shound be any of the 2 algorithms;
                    SymmetricAlgorithm symAlg = CryptographyExtensions.SymmetricFactory(this.symmetricAlgorithmUri);
                    symAlg.Key = key;
                    return symAlg;
                }
                return null;
            }
            // Fallback to the base implementation
            return base.GetDecryptionKey(encryptedData, this.symmetricAlgorithmUri);
        }

        private EncryptedKey GetEncryptedKeyfromKeyInfoClause(EncryptedData encryptedData) {
            IEnumerator keyInfoEnum = encryptedData.KeyInfo.GetEnumerator();
            KeyInfoRetrievalMethod kiRetrievalMethod;
            KeyInfoName kiName;
            KeyInfoEncryptedKey kiEncKey;
            EncryptedKey ek = null;

            while (keyInfoEnum.MoveNext()) {
                kiName = keyInfoEnum.Current as KeyInfoName;
                if (kiName != null) {
                    // Get the decryption key from the key mapping
                    string keyName = kiName.Value;
                    // try to get it from a CarriedKeyName
                    XmlNamespaceManager nsm = new XmlNamespaceManager(document.NameTable);
                    nsm.AddNamespace("enc", EncryptedXml.XmlEncNamespaceUrl);
                    XmlNodeList encryptedKeyList = document.SelectNodes("//enc:EncryptedKey", nsm);
                    if (encryptedKeyList != null) {
                        foreach (XmlNode encryptedKeyNode in encryptedKeyList) {
                            XmlElement encryptedKeyElement = encryptedKeyNode as XmlElement;
                            EncryptedKey ek1 = new EncryptedKey();
                            ek1.LoadXml(encryptedKeyElement);
                            if (ek1.CarriedKeyName == keyName && ek1.Recipient == Recipient) {
                                ek = ek1;
                                break;
                            }
                        }
                    }
                    break;
                }
                kiRetrievalMethod = keyInfoEnum.Current as KeyInfoRetrievalMethod;
                if (kiRetrievalMethod != null) {
                    string idref = UriExtensions.ExtractIdFromLocalUri(kiRetrievalMethod.Uri);
                    ek = new EncryptedKey();
                    ek.LoadXml(GetIdElement(document, idref));
                    break;
                }
                kiEncKey = keyInfoEnum.Current as KeyInfoEncryptedKey;
                if (kiEncKey != null) {
                    ek = kiEncKey.EncryptedKey;
                    break;
                }
            }
            return ek;
        }

        //Following https://csrc.nist.gov/csrc/media/publications/fips/140/2/final/documents/fips1402annexa.pdf 
        //We have only Advanced Encryption Standard(AES) and Triple-DES (TDEA) as valid key encryption and decyption algorithms
        public static bool IsSymmetricKeyRequiresFipsCompliantImplementation(string symmetricAlgorithmUri) {         
            if (symmetricAlgorithmUri != null) {
                // Check if the Uri matches AES256  or TripleDES
                if (string.Equals(symmetricAlgorithmUri, EncryptedXml.XmlEncAES256Url, StringComparison.InvariantCultureIgnoreCase)) {
                    return true;
                };
                if (string.Equals(symmetricAlgorithmUri, EncryptedXml.XmlEncTripleDESUrl, StringComparison.InvariantCultureIgnoreCase)) {
                    return true;
                };
            }                              
            return false;
        }






    }
}
