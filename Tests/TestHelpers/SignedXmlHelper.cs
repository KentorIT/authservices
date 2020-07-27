using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Xml;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography;
using Sustainsys.Saml2.Internal;
using Sustainsys.Saml2.Metadata;
using Sustainsys.Saml2.Tokens;
using System.Reflection;
using System.Collections.Generic;
using System;

namespace Sustainsys.Saml2.TestHelpers
{
    public class SignedXmlHelper
    {
        public static readonly X509Certificate2 TestCert = new X509Certificate2("Sustainsys.Saml2.Tests.pfx");

        public static readonly X509Certificate2 TestCert2 = new X509Certificate2("Sustainsys.Saml2.Tests2.pfx");

        public static readonly X509Certificate2 TestCertSignOnly = new X509Certificate2("Sustainsys.Saml2.TestsSignOnly.pfx");

        public static readonly RsaKeyIdentifierClause TestKey =
            new RsaKeyIdentifierClause((RSA)TestCert.PublicKey.Key);

        public static readonly RsaKeyIdentifierClause TestKey2 =
            new RsaKeyIdentifierClause((RSA)TestCert2.PublicKey.Key);

        public static readonly RsaKeyIdentifierClause TestKeySignOnly =
            new RsaKeyIdentifierClause((RSA)TestCertSignOnly.PublicKey.Key);

		static KeyDescriptor CreateKeyDescriptor()
		{
			var keyDescriptor = new KeyDescriptor();
			keyDescriptor.KeyInfo = new DSigKeyInfo();
			var x509Data = new X509Data();
			x509Data.Certificates.Add(TestCertSignOnly);
			keyDescriptor.KeyInfo.Data.Add(x509Data);
			return keyDescriptor;
		}

		public static readonly KeyDescriptor TestKeyDescriptor = CreateKeyDescriptor();

        public static string SignXml(
            string xml,
            bool includeKeyInfo = false,
            bool preserveWhitespace = true,
            string signingAlgorithmName = null,
            string canonicalizationMethod = null)
        {
            var xmlDoc = XmlHelpers.CreateSafeXmlDocument();
            xmlDoc.PreserveWhitespace = preserveWhitespace;
            xmlDoc.LoadXml(xml);

            if(string.IsNullOrEmpty(signingAlgorithmName))
            {
                xmlDoc.Sign(TestCert, includeKeyInfo);
            }
            else
            {
                xmlDoc.Sign(TestCert, includeKeyInfo, signingAlgorithmName, canonicalizationMethod);
            }

            return xmlDoc.OuterXml;
        }        

        public static string EncryptAssertion(string assertionXml, bool useOaep = false, X509Certificate2 certificate = null)
        {
            if (certificate == null)
            {
                certificate = TestCert2;
            }

            var xmlDoc = XmlHelpers.CreateSafeXmlDocument();
            var wrappedAssertion = $@"<saml2:EncryptedAssertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion"">{assertionXml}</saml2:EncryptedAssertion>";
            xmlDoc.LoadXml(wrappedAssertion);
            var elementToEncrypt = (XmlElement)xmlDoc.GetElementsByTagName("Assertion", Saml2Namespaces.Saml2Name)[0];

            elementToEncrypt.Encrypt(useOaep, certificate);

            return xmlDoc.OuterXml;
        }

        public static readonly string KeyInfoXml;

        public static readonly string KeyInfoXml2;

        static SignedXmlHelper()
        {
            var keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(TestCert));
            KeyInfoXml = keyInfo.GetXml().OuterXml;

            var keyInfo2 = new KeyInfo();
            keyInfo2.AddClause(new KeyInfoX509Data(TestCert2));
            KeyInfoXml2 = keyInfo2.GetXml().OuterXml;
        }
    }
}
