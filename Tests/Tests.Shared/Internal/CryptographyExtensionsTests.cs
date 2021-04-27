using FluentAssertions;
using Sustainsys.Saml2.Internal;
using Sustainsys.Saml2.TestHelpers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Xml;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography;
using NSubstitute.ExceptionExtensions;

namespace Sustainsys.Saml2.Tests.Internal
{
    [TestClass]
    public class CryptographyExtensionsTests
    {
        [TestMethod]
        public void XmlHelpers_Encrypt_OaepTrue()
        {
            var xmlDoc = XmlHelpers.XmlDocumentFromString("<xml />");
            var elementToEncrypt = xmlDoc.DocumentElement;
            elementToEncrypt.Encrypt(useOaep: true, certificate: SignedXmlHelper.TestCert);

            var nodes = new XmlElement[] { elementToEncrypt };
            nodes.Decrypt(SignedXmlHelper.TestCert.PrivateKey);

            nodes[0].OuterXml.Should().Be("<xml />");
        }

        [TestMethod]
        public void XmlHelpers_Encrypt_OaepFalse()
        {
            var xmlDoc = XmlHelpers.XmlDocumentFromString("<xml />");
            var elementToEncrypt = xmlDoc.DocumentElement;
            elementToEncrypt.Encrypt(useOaep: false, certificate: SignedXmlHelper.TestCert);

            var nodes = new XmlElement[] { elementToEncrypt };
            nodes.Decrypt(SignedXmlHelper.TestCert.PrivateKey);

            nodes[0].OuterXml.Should().Be("<xml />");
        }

        [TestMethod]
        public void XmlHelpers_Encrypt_NullCert()
        {
            XmlHelpers.CreateSafeXmlDocument().DocumentElement.Invoking(
                e => e.Encrypt(false, null))
                .Should().Throw<ArgumentNullException>()
                .And.ParamName.Should().Be("certificate");
        }

        [TestMethod]
        public void SymmetricFactory_SendAes256_AesInstanceReturned() 
        {
            var symetricInstance = CryptographyExtensions.SymmetricFactory(EncryptedXml.XmlEncAES256Url);
            symetricInstance.Should().BeOfType(typeof(AesCryptoServiceProvider));
        }

        [TestMethod]
        public void SymmetricFactory_SendTripleDES_TripleDESInstanceReturned() {
            var symetricInstance = CryptographyExtensions.SymmetricFactory(EncryptedXml.XmlEncTripleDESUrl);
            symetricInstance.Should().BeOfType(typeof(TripleDESCryptoServiceProvider));
        }

        [TestMethod]
        public void SymmetricFactory_SendOtherAlgorithmNoFips_AesInstanceReturned() {
            var symetricInstance = CryptographyExtensions.SymmetricFactory(EncryptedXml.XmlEncAES128Url);
            symetricInstance.Should().BeOfType(typeof(AesCryptoServiceProvider));
        }
    }
}
