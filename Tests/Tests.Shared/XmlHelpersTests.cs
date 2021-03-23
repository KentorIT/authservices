using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Xml;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using FluentAssertions;
using Sustainsys.Saml2.Tests.Helpers;
using Sustainsys.Saml2.Exceptions;
using System.Security.Cryptography;
using System.Reflection;
using Sustainsys.Saml2.Configuration;
using System.Linq;
using System.Xml.Linq;
using Sustainsys.Saml2.Internal;
using Sustainsys.Saml2.Metadata.Exceptions;
using Sustainsys.Saml2.Metadata.Tokens;
using Sustainsys.Saml2.TestHelpers;
using Sustainsys.Saml2.Tokens;

namespace Sustainsys.Saml2.Tests
{
    [TestClass]
    public class XmlHelpersTests
    {
        public static readonly X509Certificate2 TestCert = new X509Certificate2("Sustainsys.Saml2.Tests.pfx");

        [TestMethod]
        public void XmlHelpers_Sign_Nullcheck_xmlDocument()
        {
            XmlDocument xd = null;
            Action a = () => xd.Sign(TestCert);

            a.Should().Throw<ArgumentNullException>().And.ParamName.Should().Be("xmlDocument");
        }

        [TestMethod]
        public void XmlHelpers_Sign_Nullhceck_XmlDocument2()
        {
            XmlDocument xd = null;
            Action a = () => xd.Sign(TestCert, false, "");

            a.Should().Throw<ArgumentNullException>().And.ParamName.Should().Be("xmlDocument");
        }

        [TestMethod]
        public void XmlHelpers_Sign_Nullcheck_xmlElement()
        {
            ((XmlElement)null).Invoking(
                x => x.Sign(SignedXmlHelper.TestCert, true))
                .Should().Throw<ArgumentNullException>()
                .And.ParamName.Should().Be("xmlElement");
        }

        [TestMethod]
        public void XmlHelpers_Sign_Nullcheck_Cert()
        {
            xmlDocument.DocumentElement.Invoking(
                x => x.Sign(null, false))
                .Should().Throw<ArgumentNullException>()
                .And.ParamName.Should().Be("cert");
        }

        [TestMethod]
        public void XmlHelpers_Sign()
        {
            var xmlDoc = XmlHelpers.XmlDocumentFromString(
                "<root ID=\"rootElementId\"><content>Some Content</content></root>");

            xmlDoc.Sign(TestCert);

            var signature = xmlDoc.DocumentElement["Signature", SignedXml.XmlDsigNamespaceUrl];

            signature["SignedInfo", SignedXml.XmlDsigNamespaceUrl]
                ["Reference", SignedXml.XmlDsigNamespaceUrl].Attributes["URI"].Value
                .Should().Be("#rootElementId");

            // Default algorithms in SignedXml are rsa-sha1 and sha1. Default
            // in Saml2 are rsa-sha256 and sha256. Ensure Saml2
            // defaults are used and not SignedXml/.NET defaults.
            signature["SignedInfo"]["SignatureMethod"].GetAttribute("Algorithm")
                .Should().Be(SecurityAlgorithms.RsaSha256Signature);
            signature["SignedInfo"]["Reference"]["DigestMethod"].GetAttribute("Algorithm")
                .Should().Be(SecurityAlgorithms.Sha256Digest);

            var signedXml = new SignedXml(xmlDoc);
            signedXml.LoadXml(signature);
            signedXml.CheckSignature(TestCert, true).Should().BeTrue();
        }

        const string xmlString = "<xml a=\"b\">\n  <indented>content</indented>\n</xml>";
        readonly XmlDocument xmlDocument = XmlHelpers.XmlDocumentFromString(xmlString);

        [TestMethod]
        public void XmlHelpers_FromString()
        {
            xmlDocument.OuterXml.Should().Be(xmlString);
        }

        [TestMethod]
        public void XmlHelpers_Remove_NullcheckAttribute()
        {
            ((XmlAttributeCollection)null).Invoking(
                a => a.Remove("attributeName"))
                .Should().Throw<ArgumentNullException>()
                .And.ParamName.Should().Be("attributes");
        }

        [TestMethod]
        public void XmlHelpers_Remove_NullcheckAttributeName()
        {
            xmlDocument.DocumentElement.Attributes.Invoking(
                a => a.Remove(attributeName: null))
                .Should().Throw<ArgumentNullException>()
                .And.ParamName.Should().Be("attributeName");
        }

        [TestMethod]
        public void XmlHelpers_RemoveChild_NullcheckXmlElement()
        {
            XmlHelpers.CreateSafeXmlDocument().DocumentElement.Invoking(
                e => e.RemoveChild("name", "ns"))
                .Should().Throw<ArgumentNullException>()
                .And.ParamName.Should().Be("xmlElement");
        }

        [TestMethod]
        public void XmlHelpers_RemoveChild_NullcheckName()
        {
            xmlDocument.DocumentElement.Invoking(
                e => e.RemoveChild(null, "ns"))
                .Should().Throw<ArgumentNullException>()
                .And.ParamName.Should().Be("name");
        }

        [TestMethod]
        public void XmlHelpers_RemoveChild_NullcheckNs()
        {
            xmlDocument.DocumentElement.Invoking(
                e => e.RemoveChild("name", null))
                .Should().Throw<ArgumentNullException>()
                .And.ParamName.Should().Be("ns");
        }

        [TestMethod]
        public void XmlHelpers_IsSignedBy_NullcheckXmlElement()
        {
            ((XmlElement)null).Invoking(
                x => x.IsSignedBy(SignedXmlHelper.TestCert))
                .Should().Throw<ArgumentNullException>("xmlElement");
        }

        [TestMethod]
        public void XmlHelpers_IsSignedBy_NullcheckCertificate()
        {
            xmlDocument.DocumentElement.Invoking(
                x => x.IsSignedBy(null))
                .Should().Throw<ArgumentNullException>("certificate");
        }

        [TestMethod]
        public void XmlHelpers_IsSignedBy()
        {
            var xml = "<xml ID=\"someID\"><content>text</content></xml>";
            var xmlDoc = XmlHelpers.XmlDocumentFromString(xml);
            xmlDoc.Sign(SignedXmlHelper.TestCert);

            xmlDoc.DocumentElement.IsSignedBy(SignedXmlHelper.TestCert).Should().BeTrue();
        }

        [TestMethod]
        public void XmlHelpers_IsSignedBy_ThrowsOnWrongCert()
        {
            var xml = "<xml ID=\"someID\"><content>text</content></xml>";
            var xmlDoc = XmlHelpers.XmlDocumentFromString(xml);
            xmlDoc.Sign(SignedXmlHelper.TestCert2, true);

            xmlDoc.DocumentElement.Invoking(
                x => x.IsSignedBy(SignedXmlHelper.TestCert))
                .Should().Throw<InvalidSignatureException>()
                .And.Message.Should().Be("The signature verified correctly with the key contained in the signature, but that key is not trusted.");
        }

        [TestMethod]
        public void XmlHelpers_IsSignedBy_ThrowsOnTamperedData()
        {
            var xml = "<xml ID=\"someID\"><content>text</content></xml>";
            var xmlDoc = XmlHelpers.XmlDocumentFromString(xml);
            xmlDoc.Sign(SignedXmlHelper.TestCert);

            xmlDoc.DocumentElement["content"].InnerText = "changedText";

            xmlDoc.DocumentElement.Invoking(
                x => x.IsSignedBy(SignedXmlHelper.TestCert))
                .Should().Throw<InvalidSignatureException>()
                .And.Message.Should().Be("Signature didn't verify. Have the contents been tampered with?");
        }

        [TestMethod]
        public void XmlHelpers_IsSignedBy_TrowsOnSignatureWrapping()
        {
            var xml = "<xml ID=\"someID\"><content ID=\"content1\">text</content>"
                + "<injected>other text</injected></xml>";
            var xmlDoc = XmlHelpers.XmlDocumentFromString(xml);

            xmlDoc.DocumentElement["content"].Sign(SignedXmlHelper.TestCert, false);

            // An XML wrapping attack is created by taking a legitimate signature
            // and putting it in another element. If the reference of the signature
            // is not properly checked, the element containing the signature
            // is incorrectly trusted.
            var signatureNode = xmlDoc.DocumentElement["content"]["Signature", SignedXml.XmlDsigNamespaceUrl];
            xmlDoc.DocumentElement["content"].RemoveChild(signatureNode);
            xmlDoc.DocumentElement["injected"].AppendChild(signatureNode);

            xmlDoc.DocumentElement["injected"].Invoking(
                x => x.IsSignedBy(SignedXmlHelper.TestCert))
                .Should().Throw<InvalidSignatureException>()
                .And.Message.Should().Be("Incorrect reference on Xml signature. The reference must be to the root element of the element containing the signature.");
        }

        [TestMethod]
        public void XmlHelpers_IsSignedBy_FalseOnMissingSignature()
        {
            var xml = "<xml ID=\"someID\"><content>text</content></xml>";
            var xmlDoc = XmlHelpers.XmlDocumentFromString(xml);

            xmlDoc.DocumentElement.IsSignedBy(SignedXmlHelper.TestCert).Should().BeFalse();
        }

        [TestMethod]
        public void XmlHelpers_IsSignedBy_ThrowsOnMissingReferenceInSignature()
        {
            var signedWithoutReference = @"<saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""Saml2Response_Validate_FalseOnMissingReference"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z""><saml2:Issuer>https://idp.example.com</saml2:Issuer><saml2p:Status><saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Requester"" /></saml2p:Status><Signature xmlns=""http://www.w3.org/2000/09/xmldsig#""><SignedInfo><CanonicalizationMethod Algorithm=""http://www.w3.org/TR/2001/REC-xml-c14n-20010315"" /><SignatureMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#rsa-sha1"" /></SignedInfo><SignatureValue>tYFIoYmrzmp3H7TXm9IS8DW3buBZIb6sI2ycrn+AOnVcdYnPTJpk3ntHlqQKXNEyXgXZNdqEuFpgI1I0P0TlhM+C3rBJnflkApkxZkak5RwnJzDWTHpsSDjYcm+/XgBy3JVZJuMWb2YPaV8GB6cjBMDrENUEaoKRg+FpzPUZO1EOMcqbocXp5cHie1CkPnD1OtT/cuzMBUMpBGZMxjZwdFpOO7R3CUXh/McxKfoGUQGC3DVpt5T8uGkpj4KqZVPS/qTCRhbPRDjg73BdWbdkFpFWge8G/FgkYxr9LBE1TsrxptppO9xoA5jXwJVZaWndSMvo6TuOjUgqY2w5RTkqhA==</SignatureValue></Signature></saml2p:Response>";

            var xmlDoc = XmlHelpers.XmlDocumentFromString(signedWithoutReference);

            xmlDoc.DocumentElement.Invoking(
                x => x.IsSignedBy(SignedXmlHelper.TestCert))
                .Should().Throw<InvalidSignatureException>()
                .And.Message.Should().Be("No reference found in Xml signature, it doesn't validate the Xml data.");
        }

        [TestMethod]
        public void XmlHelpers_IsSignedBy_ThrowsOnEmptyReferencesInSignature()
        {
            var xml = "<xml ID=\"myxml\" />";

            var xmlDoc = XmlHelpers.XmlDocumentFromString(xml);

            var signedXml = new SignedXml(xmlDoc);
            signedXml.SigningKey = SignedXmlHelper.TestCert.PrivateKey;
            signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA1Url;
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

            var ref1 = new Reference { Uri = "" };
            ref1.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            ref1.AddTransform(new XmlDsigExcC14NTransform());
            signedXml.AddReference(ref1);

            signedXml.ComputeSignature();
            xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(signedXml.GetXml(), true));

            xmlDoc.DocumentElement.Invoking(
                x => x.IsSignedBy(SignedXmlHelper.TestCert))
                .Should().Throw<InvalidSignatureException>()
                .And.Message.Should().Be("Empty reference for Xml signature is not allowed.");
        }

        [TestMethod]
        public void XmlHelpers_IsSignedBy_ThrowsOnDualReferencesInSignature()
        {
            var xml = "<xml ID=\"myxml\" />";

            var xmlDoc = XmlHelpers.XmlDocumentFromString(xml);

            var signedXml = new SignedXml(xmlDoc);
            signedXml.SigningKey = SignedXmlHelper.TestCert.PrivateKey;
            signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA1Url;
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

            var ref1 = new Reference { Uri = "#myxml" };
            ref1.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            ref1.AddTransform(new XmlDsigExcC14NTransform());
            signedXml.AddReference(ref1);

            var ref2 = new Reference { Uri = "#myxml" };
            ref2.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            ref2.AddTransform(new XmlDsigExcC14NTransform());
            signedXml.AddReference(ref2);

            signedXml.ComputeSignature();
            xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(signedXml.GetXml(), true));

            xmlDoc.DocumentElement.Invoking(
                x => x.IsSignedBy(SignedXmlHelper.TestCert))
                .Should().Throw<InvalidSignatureException>()
                .And.Message.Should().Be("Multiple references for Xml signatures are not allowed.");
        }

        [TestMethod]
        public void XmlHelpers_IsSignedBy_ThrowsOnTamperedData_WithSha256Signature()
        {
            var xml = @"<Assertion ID=""Saml2Response_GetClaims_FailsSha256WhenChanged"" IssueInstant=""2015-03-13T20:44:00.791Z"" Version=""2.0"" xmlns=""urn:oasis:names:tc:SAML:2.0:assertion""><Issuer>https://idp.example.com</Issuer><Signature xmlns=""http://www.w3.org/2000/09/xmldsig#""><SignedInfo><CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /><SignatureMethod Algorithm=""http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"" /><Reference URI=""#Saml2Response_GetClaims_FailsSha256WhenChanged""><Transforms><Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature"" /><Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /></Transforms><DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" /><DigestValue>BKRyWqweAczLA8fgRcx6zzMDiP0qT0TwqU/X4VgLiXM=</DigestValue></Reference></SignedInfo><SignatureValue>iK8s+MkLlixSSQu5Q/SHRZLhfnj4jlyPLAD6C2n9zmQu4CosZME7mxiNFiWyOE8XRGd+2LJle+NjJrkZFktVb03JaToq7w4Q8GfJ2oUUjNCweoaJ6NzsnwkFoXhyh0dfOixl/Ifa3qDX50/Hv2twF/QXfDs08GZTxZKehKsVDITyVd6nytF8VUb0+nU7UMWPn1XeHM7YNI/1mkVbCRx/ci5ZRxwjAX40xttd4JL6oBnp5oaaMgWpAa2cVb+t/9HhCRThEho1etbPHx/+E9ElL1PhKqKX6nh2GSH1TFJkwEXIPPZKqCs3YDINLBZpLfl626zbV4cGOGyWUAroVsk2uw==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIDIzCCAg+gAwIBAgIQg7mOjTf994NAVxZu4jqXpzAJBgUrDgMCHQUAMCQxIjAgBgNVBAMTGUtlbnRvci5BdXRoU2VydmljZXMuVGVzdHMwHhcNMTMwOTI1MTMzNTQ0WhcNMzkxMjMxMjM1OTU5WjAkMSIwIAYDVQQDExlLZW50b3IuQXV0aFNlcnZpY2VzLlRlc3RzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwVGpfvK9N//MnA5Jo1q2liyPR24406Dp25gv7LB3HK4DWgqsb7xXM6KIV/WVOyCV2g/O1ErBlB+HLhVZ4XUJvbqBbgAJqFO+TZwcCIe8u4nTEXeU660FdtkKClA17sbtMrAGdDfOPwVBHSuavdHeD7jHNI4RUDGKnEW13/0EvnHDilIetwODRxrX/+41R24sJThFbMczByS3OAL2dcIxoAynaGeM90gXsVYow1QhJUy21+cictikb7jW4mW6dvFCBrWIceom9J295DcQIHoxJy5NoZwMir/JV00qs1wDVoN20Ve1DC5ImwcG46XPF7efQ44yLh2j5Yexw+xloA81dwIDAQABo1kwVzBVBgNVHQEETjBMgBAWIahoZhXVUogbAqkS7zwfoSYwJDEiMCAGA1UEAxMZS2VudG9yLkF1dGhTZXJ2aWNlcy5UZXN0c4IQg7mOjTf994NAVxZu4jqXpzAJBgUrDgMCHQUAA4IBAQA2aGzmuKw4AYXWMhrGj5+i8vyAoifUn1QVOFsUukEA77CrqhqqaWFoeagfJp/45vlvrfrEwtF0QcWfmO9w1VvHwm7sk1G/cdYyJ71sU+llDsdPZm7LxQvWZYkK+xELcinQpSwt4ExavS+jLcHoOYHYwIZMBn3U8wZw7Kq29oGnoFQz7HLCEl/G9i3QRyvFITNlWTjoScaqMjHTzq6HCMaRsL09DLcY3KB+cedfpC0/MBlzaxZv0DctTulyaDfM9DCYOyokGN/rQ6qkAR0DDm8fVwknbJY7kURXNGoUetulTb5ow8BvD1gncOaYHSD0kbHZG+bLsUZDFatEr2KW8jbG</X509Certificate></X509Data></KeyInfo></Signature><Subject><NameID>SomeUser</NameID><SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" /></Subject><Conditions NotOnOrAfter=""2100-01-01T05:00:00.000Z"" /></Assertion>";
            xml = xml.Replace("SomeUser", "OtherUser");

            var xmlDoc = XmlHelpers.XmlDocumentFromString(xml);

            xmlDoc.DocumentElement.Invoking(
                x => x.IsSignedBy(SignedXmlHelper.TestCert))
                .Should().Throw<InvalidSignatureException>()
                .WithMessage("Signature didn't verify. Have the contents been tampered with?");
        }

        [TestMethod]
        public void XmlHelpers_IsSignedBy_ThrowsOnIncorrectTransformsInSignature()
        {
            // SAML2 Core 5.4.4 states that signatures SHOULD NOT contain other transforms than
            // the enveloped signature or exclusive canonicalization transforms and that a verifier
            // of a signature MAY reject signatures with other transforms. We'll reject them to
            // mitigate the risk of transforms opening up for assertion injections.

            var xml = "<xml ID=\"MyXml\" />";

            var xmlDoc = XmlHelpers.XmlDocumentFromString(xml);

            var signedXml = new SignedXml(xmlDoc);
            signedXml.SigningKey = SignedXmlHelper.TestCert.PrivateKey;
            signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA1Url;
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

            var reference = new Reference { Uri = "#MyXml" };
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigC14NTransform()); // The allowed transform is XmlDsigExcC14NTransform
            signedXml.AddReference(reference);

            signedXml.ComputeSignature();
            xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(signedXml.GetXml(), true));

            xmlDoc.DocumentElement.Invoking(
                x => x.IsSignedBy(SignedXmlHelper.TestCert))
                .Should().Throw<InvalidSignatureException>()
                .And.Message.Should().Be("Transform \"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\" found in Xml signature SHOULD NOT be used with SAML2.");
        }

        [TestMethod]
        public void XmlHelpers_IsSignedBy_HandlesMultipleSignaturesInSameDocument()
        {
            var content1 = SignedXmlHelper.SignXml("<content ID=\"c1\" />");
            var content2 = SignedXmlHelper.SignXml("<content ID=\"c2\" />");

            var xml =
$@"<xml>
    {content1}
    {content2}
</xml>";

            var xmlDoc = XmlHelpers.XmlDocumentFromString(xml);

            ((XmlElement)xmlDoc.SelectSingleNode("//*[@ID=\"c1\"]")).IsSignedBy(SignedXmlHelper.TestCert)
                .Should().BeTrue("first content is correclty signed");

            ((XmlElement)xmlDoc.SelectSingleNode("//*[@ID=\"c2\"]")).IsSignedBy(SignedXmlHelper.TestCert)
                .Should().BeTrue("second content is correclty signed");
        }

        class StubKeyIdentifier : SecurityKeyIdentifierClause
        {
            public StubKeyIdentifier() : base("Stub")
            {
            }

            public override SecurityKey CreateKey()
            {
                throw new CryptographicException("Stub key identifier throwing");
            }
        }

        [TestMethod]
        public void XmlHelpers_IsSignedBy_DoesNotThrowSha256MessageForOtherProblem()
        {
            // Here I've specified an invalid digest algorithm. Want to be sure it
            // does NOT flag this as a problem with the sha256 signature algorithm 
            // (they both throw CryptographicException)
            var xml =
                @"<Assertion ID=""Saml2Response_GetClaims_DoesNotThrowSha256MessageForOtherProblem_Assertion"" IssueInstant=""2015-03-13T20:43:07.330Z"" Version=""2.0"" xmlns=""urn:oasis:names:tc:SAML:2.0:assertion""><Issuer>https://idp.example.com</Issuer><Signature xmlns=""http://www.w3.org/2000/09/xmldsig#""><SignedInfo><CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /><SignatureMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#rsa-sha1"" /><Reference URI=""#Saml2Response_GetClaims_DoesNotThrowSha256MessageForOtherProblem_Assertion""><Transforms><Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature"" /><Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /></Transforms><DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" /><DigestValue>F+E7u3vqMC07ipvP9AowsMqP7y6CsAC0GeEIxNSwDEI=</DigestValue></Reference></SignedInfo><SignatureValue>GmiXn24Ccnr64TbmDd1/nLM+891z0FtRHSpU8+75uOqbpNK/ZZGrltFf2YZ5u9b9O0HfbFFsZ0i28ocwAZOv2UfxQrCtOGf3ss7Q+t2Zmc6Q/3ES7HIa15I5BbaSdNfpOMlX6N1XXhMprRGy2YWMr5IAIhysFG1A2oHaC3yFiesfUrawN/lXUYuI22Kf4A5bmnIkKijnwX9ewnhRj6569bw+c6q+tVZSHQzI+KMU9KbKN4NsXxAmv6dM1w2qOiX9/CO9LzwEtlhA9yo3sl0uWP8z5GwK9qgOlsF2NdImAQ5f0U4Uv26doFn09W+VExFwNhcXhewQUuPBYBr+XXzdww==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIDIzCCAg+gAwIBAgIQg7mOjTf994NAVxZu4jqXpzAJBgUrDgMCHQUAMCQxIjAgBgNVBAMTGUtlbnRvci5BdXRoU2VydmljZXMuVGVzdHMwHhcNMTMwOTI1MTMzNTQ0WhcNMzkxMjMxMjM1OTU5WjAkMSIwIAYDVQQDExlLZW50b3IuQXV0aFNlcnZpY2VzLlRlc3RzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwVGpfvK9N//MnA5Jo1q2liyPR24406Dp25gv7LB3HK4DWgqsb7xXM6KIV/WVOyCV2g/O1ErBlB+HLhVZ4XUJvbqBbgAJqFO+TZwcCIe8u4nTEXeU660FdtkKClA17sbtMrAGdDfOPwVBHSuavdHeD7jHNI4RUDGKnEW13/0EvnHDilIetwODRxrX/+41R24sJThFbMczByS3OAL2dcIxoAynaGeM90gXsVYow1QhJUy21+cictikb7jW4mW6dvFCBrWIceom9J295DcQIHoxJy5NoZwMir/JV00qs1wDVoN20Ve1DC5ImwcG46XPF7efQ44yLh2j5Yexw+xloA81dwIDAQABo1kwVzBVBgNVHQEETjBMgBAWIahoZhXVUogbAqkS7zwfoSYwJDEiMCAGA1UEAxMZS2VudG9yLkF1dGhTZXJ2aWNlcy5UZXN0c4IQg7mOjTf994NAVxZu4jqXpzAJBgUrDgMCHQUAA4IBAQA2aGzmuKw4AYXWMhrGj5+i8vyAoifUn1QVOFsUukEA77CrqhqqaWFoeagfJp/45vlvrfrEwtF0QcWfmO9w1VvHwm7sk1G/cdYyJ71sU+llDsdPZm7LxQvWZYkK+xELcinQpSwt4ExavS+jLcHoOYHYwIZMBn3U8wZw7Kq29oGnoFQz7HLCEl/G9i3QRyvFITNlWTjoScaqMjHTzq6HCMaRsL09DLcY3KB+cedfpC0/MBlzaxZv0DctTulyaDfM9DCYOyokGN/rQ6qkAR0DDm8fVwknbJY7kURXNGoUetulTb5ow8BvD1gncOaYHSD0kbHZG+bLsUZDFatEr2KW8jbG</X509Certificate></X509Data></KeyInfo></Signature><Subject><NameID>SomeUser</NameID><SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" /></Subject><Conditions NotOnOrAfter=""2100-01-01T05:00:00.000Z"" /></Assertion>";

            var xmlDoc = XmlHelpers.XmlDocumentFromString(xml);

            xmlDoc.DocumentElement.Invoking(x => x.IsSignedByAny(
                Enumerable.Repeat(new StubKeyIdentifier(), 1), false, SignedXml.XmlDsigRSASHA1Url))
                .Should().Throw<CryptographicException>()
                .WithMessage("Stub*");
        }

        [TestMethod]
        public void XmlHelpers_IsSignedBy_ChecksSigningAlgorithmStrength()
        {
            var xml = "<xml ID=\"MyXml\" />";

            var xmlDoc = XmlHelpers.XmlDocumentFromString(xml);
            var sx = new SignedXml(xmlDoc);

            var reference = new Reference
            {
                Uri = "#MyXml",
                DigestMethod = SecurityAlgorithms.Sha256Digest
            };
            reference.AddTransform(new XmlDsigExcC14NTransform());
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            sx.AddReference(reference);
            sx.SigningKey = SignedXmlHelper.TestCert.PrivateKey.GetSha256EnabledAsymmetricAlgorithm();

            sx.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA1Url;
            sx.ComputeSignature();
            xmlDoc.DocumentElement.AppendChild(sx.GetXml());

            var keyClause = new X509RawDataKeyIdentifierClause(SignedXmlHelper.TestCert);

            xmlDoc.DocumentElement.Invoking(x =>
            x.IsSignedByAny(Enumerable.Repeat(keyClause, 1), false, SecurityAlgorithms.RsaSha256Signature))
            .Should().Throw<InvalidSignatureException>()
            .WithMessage("*signing*weak*");
        }

        [TestMethod]
        public void XmlHelpers_IsSignedBy_ChecksDigestAlgorithmStrength()
        {
            var xml = "<xml ID=\"MyXml\" />";

            var xmlDoc = XmlHelpers.XmlDocumentFromString(xml);
            var sx = new SignedXml(xmlDoc);

            var reference = new Reference
            {
                Uri = "#MyXml",
                DigestMethod = SignedXml.XmlDsigSHA1Url
            };
            reference.AddTransform(new XmlDsigExcC14NTransform());
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            sx.AddReference(reference);
            sx.SigningKey = SignedXmlHelper.TestCert.PrivateKey.GetSha256EnabledAsymmetricAlgorithm();

            sx.SignedInfo.SignatureMethod = SecurityAlgorithms.RsaSha256Signature;
            sx.ComputeSignature();
            xmlDoc.DocumentElement.AppendChild(sx.GetXml());

            var keyClause = new X509RawDataKeyIdentifierClause(SignedXmlHelper.TestCert);

            xmlDoc.DocumentElement.Invoking(x =>
            x.IsSignedByAny(Enumerable.Repeat(keyClause, 1), false, SecurityAlgorithms.RsaSha256Signature))
            .Should().Throw<InvalidSignatureException>()
            .WithMessage("*digest*weak*");
        }

        [TestMethod]
        public void XmlHelpers_IsSignedByAny_ThrowsOnCertValidationWithRsaKey()
        {
            var xml = "<xml ID=\"MyXml\" />";

            var xmlDoc = XmlHelpers.XmlDocumentFromString(xml);
            xmlDoc.Sign(SignedXmlHelper.TestCert, false);

            var signingKeys = Enumerable.Repeat(SignedXmlHelper.TestKey, 1);

            xmlDoc.DocumentElement.Invoking(x => x.IsSignedByAny(signingKeys, true, SignedXml.XmlDsigRSASHA1Url))
                .Should().Throw<InvalidOperationException>()
                .And.Message.Should().Be("Certificate validation enabled, but the signing key identifier is of type RsaKeyIdentifierClause which cannot be validated as a certificate.");
        }

        [TestMethod]
        public void XmlHelpers_AddAttributeIfNotNullOrEmpty_Adds()
        {
            var e = new XElement("xml");

            e.AddAttributeIfNotNullOrEmpty("attribute", "value");

            e.Attribute("attribute").Should().NotBeNull().And.Subject.Value
                .Should().Be("value");
        }

        [TestMethod]
        public void XmlHelpers_AddAttributeIfNotNullOrEmpty_IgnoresEmpty()
        {
            var e = new XElement("xml");

            e.AddAttributeIfNotNullOrEmpty("attribute", "");

            e.Attribute("attribute").Should().BeNull();
        }

        [TestMethod]
        public void XmlHelpers_AddAttributeIfNotNullOrEmpty_HandlesNamespace()
        {
            var e = new XElement("xml");

            var ns = XNamespace.Get("someNamespace");

            e.AddAttributeIfNotNullOrEmpty(ns + "attribute", "");

            e.Attribute(ns + "attribute").Should().BeNull();
        }

        [TestMethod]
        public void XmlHelpers_AddAttributeIfNotNullOrEmpty_IgnoresNull()
        {
            var e = new XElement("xml");

            e.AddAttributeIfNotNullOrEmpty("attribute", null);

            e.Attribute("attribute").Should().BeNull();
        }

        [TestMethod]
        public void XmlHelpers_AddAttributeIfNotNullOrEmpty_HandlesUri()
        {
            var e = new XElement("xml");

            string uri = "http://some.example.com/";
            e.AddAttributeIfNotNullOrEmpty("attribute", new Uri(uri));

            e.Attribute("attribute").Should().NotBeNull().And.Subject.Value.Should().Be(uri);
        }

        class EmptyToString { public override string ToString() { return string.Empty; } }

        [TestMethod]
        public void XmlHelpers_AddAttributeIfNotNullOrEmpty_IgnoresObjectWithEmptyToString()
        {
            var e = new XElement("xml");

            e.AddAttributeIfNotNullOrEmpty("attribute", new EmptyToString());

            e.Attribute("attribute").Should().BeNull();
        }

        [TestMethod]
        public void XmlHelpers_AddAttributeIfNotNullOrEmtpy_TimeSpanSerializedCorrectly()
        {
            // It might be tempting in the implementation to call value.ToString()
            // instead of passing in the value. That would make types that have
            // special XML Serialization formats fail. This test ensures that
            // nobody takes that shortcut without handling the special cases.

            var e = new XElement("xml");

            e.AddAttributeIfNotNullOrEmpty("attribute", new TimeSpan(2, 17, 32));

            e.Attribute("attribute").Should().NotBeNull().And.Subject.Value.Should().Be("PT2H17M32S");
        }

        [TestMethod]
        public void XmlHelpers_GetValueIfNotNull_NullOnNull()
        {
            XmlAttribute x = null;
            x.GetValueIfNotNull().Should().BeNull();
        }

        [TestMethod]
        public void XmlHelpers_GetValueIfNotNull_ValueOnNotNull()
        {
            var xd = XmlHelpers.CreateSafeXmlDocument();
            var a = xd.CreateAttribute("someAttribute");
            a.Value = "SomeValue";

            a.GetValueIfNotNull().Should().Be("SomeValue");
        }

        [TestMethod]
        public void XmlHelpers_GetTrimmedTextIfNotNull_ValueOnNotNull()
        {
            var xd = XmlHelpers.CreateSafeXmlDocument();
            var e = xd.CreateElement("someElement");
            e.InnerText = "\r\n     Some Text";

            e.GetTrimmedTextIfNotNull().Should().Be("Some Text");
        }

        [TestMethod]
        public void XmlHelpers_GetTrimmedTextIfNotNull_NullOnNull()
        {
            XmlElement e = null;

            e.GetTrimmedTextIfNotNull().Should().BeNull();
        }

        [TestMethod]
        public void XmlHelpers_PrettyPrint_Nullcheck()
        {
            Action a = () => ((XmlElement)null).PrettyPrint();

            a.Should().Throw<ArgumentNullException>()
                .And.ParamName.Should().Be("xml");
        }

        [TestMethod]
        public void XmlHelpers_PrettyPrint()
        {
            var xmlDoc = XmlHelpers.CreateSafeXmlDocument();
            xmlDoc.LoadXml("<a><b>c</b></a>");

            var result = xmlDoc.DocumentElement.PrettyPrint();

            var parsed = XmlHelpers.XmlDocumentFromString(result);

            var expected = "<a>\r\n  <b>c</b>\r\n</a>";

            parsed.OuterXml.Should().Be(expected);
            // Don't change semantics.
            parsed.DocumentElement.Should().BeEquivalentTo(xmlDoc.DocumentElement);
        }

        [TestMethod]
        public void XmlHelpers_GetFullSigningAlgorithmName_MapsSha256()
        {
            var shortName = "sha256";

            var expected = SecurityAlgorithms.RsaSha256Signature;

            XmlHelpers.GetFullSigningAlgorithmName(shortName)
                .Should().Be(expected);
        }

        [TestMethod]
        public void XmlHelpers_GetFullSigningAlgorithmName_MapsSHA256()
        {
            var shortName = "SHA256";

            var expected = SecurityAlgorithms.RsaSha256Signature;

            XmlHelpers.GetFullSigningAlgorithmName(shortName)
                .Should().Be(expected);
        }

        [TestMethod]
        public void XmlHelpers_GetFullSigningAlgorithmName_DefaultsToSha256IfAvailable()
        {
            var expected = SecurityAlgorithms.RsaSha256Signature;

            XmlHelpers.GetFullSigningAlgorithmName("")
                .Should().Be(expected);
        }

        [TestMethod]
        public void XmlHelpers_GetCorrespondingDigestAlgorithmName_Sha256()
        {
            XmlHelpers.GetCorrespondingDigestAlgorithm(SecurityAlgorithms.RsaSha256Signature)
                .Should().Be(SecurityAlgorithms.Sha256Digest);
        }

        [TestMethod]
        public void XmlHelpers_CreateSafeXmlDocument()
        {
            var actual = XmlHelpers.CreateSafeXmlDocument();

            var field = typeof(XmlDocument).GetField("_resolver", BindingFlags.NonPublic | BindingFlags.Instance);
            if (field == null)
            {
                field = typeof(XmlDocument).GetField("resolver", BindingFlags.NonPublic | BindingFlags.Instance);
            }

            field.GetValue(actual).Should().BeNull();

            actual.PreserveWhitespace.Should().BeTrue();
        }
    }
}