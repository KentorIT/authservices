using FluentAssertions;
using Sustainsys.Saml2.Internal;
using Sustainsys.Saml2.TestHelpers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography;
using Sustainsys.Saml2.Tests.Helpers;
using System.Collections;

namespace Sustainsys.Saml2.Tests.Internal {
    [TestClass]
    public class RSAEncryptedXmlTests {

       private EncryptedData _encryptedData;

        [TestMethod]
        public void GetDecryptionKey_KeyInfoEncryptedKeyNode_Decrypted() {
                var exml = InitializeTestXMLElements(EncryptedXml.XmlEncAES256Url, "KeyInfoEncryptedKey", true);
                exml.GetDecryptionKey(_encryptedData, null).Should().BeOfType(typeof(AesCryptoServiceProvider));          
        }
        //If Fips is enabled in machine then a Cryptographic exception is expected on base implementation
        //Then if no fips enabled we expect to have a  RijndaelManaged instance for this scenario
        [TestMethod]
        public void GetDecryptionKey_NonFipsAlgorithm_SymmetricAlgorithmReturned() {         
            var exml = InitializeTestXMLElements(EncryptedXml.XmlEncAES192Url, "KeyInfoEncryptedKey", true, null, true, true, true, false);
            if (CryptoConfig.AllowOnlyFipsAlgorithms) {
                exml.Invoking(e => e.GetDecryptionKey(_encryptedData, null)).Should().Throw<CryptographicException>();
            }else {
                exml.GetDecryptionKey(_encryptedData, null).Should().BeOfType(typeof(RijndaelManaged));
            }           
        }

        [TestMethod]
        public void GetDecryptionKey_NullEncryptedData_ThrowArgumentNullException() {
            var exml = InitializeTestXMLElements(EncryptedXml.XmlEncAES256Url, "KeyInfoEncryptedKey", true);
            exml.Invoking(e => e.GetDecryptionKey(null, null)).Should().Throw<ArgumentNullException>()
                 .Where(e => e.ParamName.Equals("No Encrypted Data Provided"));           
        }


        [TestMethod]
        public void GetDecryptionKey_NullKeyInfo_NullReturned() {
            var exml = InitializeTestXMLElements(EncryptedXml.XmlEncAES256Url, "KeyInfoEncryptedKey", false);
            exml.GetDecryptionKey(_encryptedData, null).Should().BeNull();
        }

        [TestMethod]
        public void GetDecryptionKey_NoEncryptedMethod_ThrowCryptographicException() {
            var exml = InitializeTestXMLElements(EncryptedXml.XmlEncAES256Url, "KeyInfoEncryptedKey", true, null, false);
            exml.Invoking(e => e.GetDecryptionKey(_encryptedData, null)).Should().Throw<CryptographicException>()
                 .Where(e => e.Message.Equals("No Cryptograpy algorithm provided in encryption method"));
        }

        [TestMethod]
        public void GetDecryptionKey_NoKeyResolved_ThrowCryptographicException() {
            var exml = InitializeTestXMLElements(EncryptedXml.XmlEncAES256Url, "KeyInfoEncryptedKey", true, null, true, false);
            exml.Invoking(e => e.GetDecryptionKey(_encryptedData, null)).Should().Throw<CryptographicException>()
                 .Where(e => e.Message.Equals("No Decryption Key found"));
        }

        [TestMethod]
        public void GetDecryptionKey_NoEncryptedKeyLoaded_ReturnNull() {
            var exml = InitializeTestXMLElements(EncryptedXml.XmlEncAES256Url, "KeyInfoName", true, null, true, false, false);           
            exml.GetDecryptionKey(_encryptedData, null).Should().BeNull();
        }

        [TestMethod]
        public void GetEncryptedKeyfromKeyInfoClause_KeyName_SymmetricAlgorithmReturned() {
            var exml = InitializeTestXMLElements(EncryptedXml.XmlEncAES256Url, "KeyInfoName", true, "AESKey");
            exml.GetDecryptionKey(_encryptedData, null).Should().BeOfType(typeof(AesCryptoServiceProvider));
        }

        [TestMethod]
        public void GetEncryptedKeyfromKeyInfoClause_KeyInfoRetrievalMethod_SymmetricAlgorithmReturned() {
            var exml = InitializeTestXMLElements(EncryptedXml.XmlEncAES256Url, "KeyInfoRetrievalMethod", true);
            exml.GetDecryptionKey(_encryptedData, null).Should().BeOfType(typeof(AesCryptoServiceProvider));
        }

        [TestMethod]
        public void IsSymmetricKeyRequiresFipsCompliantImplementation_TripleDESUri_ReturnTrue() {
            RSAEncryptedXml.IsSymmetricKeyRequiresFipsCompliantImplementation(EncryptedXml.XmlEncTripleDESUrl).Should().BeTrue();
        }

        [TestMethod]
        public void IsSymmetricKeyRequiresFipsCompliantImplementation_NoFipsUri_ReturnFalse() {
            RSAEncryptedXml.IsSymmetricKeyRequiresFipsCompliantImplementation(EncryptedXml.XmlEncAES192Url).Should().BeFalse();
        }

        [TestMethod]
        public void DecryptEncryptedKey_DecryptOpaep_ByteArrayReturne() {
            var exml = InitializeTestXMLElements(EncryptedXml.XmlEncAES256Url, "KeyInfoEncryptedKey", true);
            IEnumerator keyInfoEnum = _encryptedData.KeyInfo.GetEnumerator();
            EncryptedKey ek;
            while (keyInfoEnum.MoveNext()){
                KeyInfoEncryptedKey ki = keyInfoEnum.Current as KeyInfoEncryptedKey;
                ek = ki.EncryptedKey;
                exml.DecryptEncryptedKey(ek).Should().BeOfType(typeof(byte[]));
                break;
            }                       
        }

        [TestMethod]
        public void DecryptEncryptedKey_DecryptNotOpaep_ByteArrayReturne() {
            var exml = InitializeTestXMLElements(EncryptedXml.XmlEncAES256Url, "KeyInfoEncryptedKey", true, null, true, true, true, false);
            IEnumerator keyInfoEnum = _encryptedData.KeyInfo.GetEnumerator();
            EncryptedKey ek;
            while (keyInfoEnum.MoveNext()) {
                KeyInfoEncryptedKey ki = keyInfoEnum.Current as KeyInfoEncryptedKey;
                ek = ki.EncryptedKey;
                exml.DecryptEncryptedKey(ek).Should().BeOfType(typeof(byte[]));
                break;
            }
        }

        [TestMethod]
        public void DecryptEncryptedKey_NullEncryptedKey_ThrowArgumentNullException() {
            var exml = InitializeTestXMLElements(EncryptedXml.XmlEncAES256Url, "KeyInfoEncryptedKey", true);
            exml.Invoking(e => e.DecryptEncryptedKey(null)).Should().Throw<ArgumentNullException>();
        }

        [TestMethod]
        public void DecryptEncryptedKey_NullOrEmptyCypherValue_ThrowNotImplementedException() {
            var exml = InitializeTestXMLElements(EncryptedXml.XmlEncAES256Url, "KeyInfoEncryptedKey", true);
            IEnumerator keyInfoEnum = _encryptedData.KeyInfo.GetEnumerator();
            EncryptedKey ek;
            while (keyInfoEnum.MoveNext()) {
                KeyInfoEncryptedKey ki = keyInfoEnum.Current as KeyInfoEncryptedKey;
                ek = ki.EncryptedKey;
                ek.CipherData.CipherValue = new byte[] {};
                exml.Invoking(e => e.DecryptEncryptedKey(ek)).Should().Throw<NotImplementedException>()
                   .Where(e => e.Message.Equals("Unable to decode CipherData of type \"CipherReference\"."));
                break;
            }
        }

        [TestMethod]
        public void DecryptEncryptedKey_NullPrivateKey_ReturnNull() {
            var exml = InitializeTestXMLElements(EncryptedXml.XmlEncAES256Url, "KeyInfoEncryptedKey", true, null, true, false, true);
            IEnumerator keyInfoEnum = _encryptedData.KeyInfo.GetEnumerator();
            EncryptedKey ek;
            while (keyInfoEnum.MoveNext()) {
                KeyInfoEncryptedKey ki = keyInfoEnum.Current as KeyInfoEncryptedKey;
                ek = ki.EncryptedKey;
                exml.DecryptEncryptedKey(ek).Should().BeNull();
                break;
            }
        }

        private RSAEncryptedXml InitializeTestXMLElements(string encryptionAlgorithm, string keyInfoClause
            ,bool generateKeyInfo, string keyName = null, bool loadEncryptedMethod = true, bool sendKey = true
            ,bool loadEncryptedKey = true, bool useOpaep = true) {
            RSA key = null;
            var xmlDoc = XmlHelpers.XmlDocumentFromString("<xml />");
            var elementToEncrypt = xmlDoc.DocumentElement;
            elementToEncrypt.EncryptWithClause(useOpaep, SignedXmlHelper.TestCert
                , keyInfoClause, keyName, encryptionAlgorithm, generateKeyInfo , loadEncryptedMethod, loadEncryptedKey
                , out var encryptedData);
            _encryptedData = encryptedData;
			if (sendKey) {
                key = (RSA)SignedXmlHelper.TestCert.PrivateKey;
			}
            return new RSAEncryptedXml(xmlDoc, key);
        }
    }
}
