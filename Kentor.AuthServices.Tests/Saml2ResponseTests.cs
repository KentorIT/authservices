﻿using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Xml;
using System.Linq;
using System.Security.Cryptography.Xml;

namespace Kentor.AuthServices.Tests
{
    [TestClass]
    public class Saml2ResponseTests
    {
        [TestMethod]
        public void Saml2Response_Read_BasicParams()
        {
            string response =
            @"<?xml version=""1.0"" encoding=""UTF-8""?>
                <saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            ID = ""Saml2Response_Read_BasicParams"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z""
            Destination=""http://destination.example.com"">
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Requester"" />
                </saml2p:Status>
            </saml2p:Response>";

            var expected = new
            {
                Id = new Saml2Id("Saml2Response_Read_BasicParams"),
                IssueInstant = new DateTime(2013, 01, 01, 0, 0, 0, DateTimeKind.Utc),
                Status = Saml2StatusCode.Requester,
                Issuer = (string)null,
                DestinationUri = new Uri("http://destination.example.com"),
                MessageName = "SAMLResponse"
            };

            Saml2Response.Read(response).ShouldBeEquivalentTo(expected,
                opt => opt.Excluding(s => s.XmlDocument));
        }

        [TestMethod]
        public void Saml2Response_Read_ThrowsOnNonXml()
        {
            Action a = () => Saml2Response.Read("not xml");

            a.ShouldThrow<XmlException>();
        }

        [TestMethod]
        public void Saml2Response_Read_ThrowsWrongRootNodeName()
        {
            Action a = () => Saml2Response.Read("<saml2p:NotResponse xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\" />");

            a.ShouldThrow<XmlException>()
                .WithMessage("Expected a SAML2 assertion document");
        }

        [TestMethod]
        public void Saml2Response_Read_ThrowsWrongRootNamespace()
        {
            Action a = () => Saml2Response.Read("<saml2p:Response xmlns:saml2p=\"something\" /> ");
            a.ShouldThrow<XmlException>()
                .WithMessage("Expected a SAML2 assertion document");
        }

        [TestMethod]
        public void Saml2Response_Read_ThrowsOnWrongVersion()
        {
            Action a = () => Saml2Response.Read("<saml2p:Response xmlns:saml2p=\""
                + Saml2Namespaces.Saml2P + "\" Version=\"wrong\" />");

            a.ShouldThrow<XmlException>()
                .WithMessage("Wrong or unsupported SAML2 version");

        }

        [TestMethod]
        public void Saml2Response_Read_Issuer()
        {
            var response =
            @"<?xml version=""1.0"" encoding=""UTF-8""?>
            <saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            ID = ""Saml2Respons_Read_Issuer"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z"">
            <saml2:Issuer xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion"">
                https://some.issuer.example.com
            </saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Requester"" />
                </saml2p:Status>
            </saml2p:Response>";

            Saml2Response.Read(response).Issuer.Should().Be("https://some.issuer.example.com");
        }

        [TestMethod]
        public void Saml2Response_Validate_FalseOnMissingSignatureInResponseAndAnyAssertion()
        {
            var response =
            @"<?xml version=""1.0"" encoding=""UTF-8""?>
            <saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            ID = ""Saml2Response_Validates_FalseOnMissingSignatureInResponseAndAnyAssertion"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z""
            Issuer = ""https://some.issuer.example.com"">
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Requester"" />
                </saml2p:Status>
                <saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_Validates_FalseOnMissingSignatureInResponseAndAnyAssertion_Assertion1""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>
                <saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_Validates_FalseOnMissingSignatureInResponseAndAnyAssertion_Assertion2""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>
            </saml2p:Response>";

            Saml2Response.Read(response).Validate(null).Should().BeFalse();
        }

        [TestMethod]
        public void Saml2Response_Validate_TrueOnCorrectSignedResponseMessage()
        {
            var response =
            @"<saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            ID = ""Saml2Response_Validate_TrueOnCorrectSignedResponseMessage"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z""
            Issuer = ""https://some.issuer.example.com"">
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Requester"" />
                </saml2p:Status>
                <saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_Validate_TrueOnCorrectSignedResponseMessage_Assertion1""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>
            </saml2p:Response>";

            var signedResponse = SignedXmlHelper.SignXml(response);

            Saml2Response.Read(signedResponse).Validate(SignedXmlHelper.TestCert).Should().BeTrue();
        }

        [TestMethod]
        public void Saml2Response_Validate_TrueOnCorrectSignedSingleAssertionInResponseMessage()
        {
            var response =
            @"<saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            ID = ""Saml2Response_Validate_TrueOnCorrectSignedSingleAssertionInResponseMessage"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z""
            Issuer = ""https://some.issuer.example.com"">
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Requester"" />
                </saml2p:Status>
                {0}
            </saml2p:Response>";

            var assertion =
            @"<saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_Validate_TrueOnCorrectSignedSingleAssertionInResponseMessagee_Assertion1""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>";


            var signedAssertion = SignedXmlHelper.SignXml(assertion);
            var signedResponse = string.Format(response, signedAssertion);

            Saml2Response.Read(signedResponse).Validate(SignedXmlHelper.TestCert).Should().BeTrue();
        }

        [TestMethod]
        public void Saml2Response_Validate_TrueOnCorrectSignedMultipleAssertionInResponseMessage()
        {
            var response =
            @"<saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            ID = ""Saml2Response_Validate_TrueOnCorrectSignedMultipleAssertionInResponseMessage"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z""
            Issuer = ""https://some.issuer.example.com"">
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Requester"" />
                </saml2p:Status>
                {0}
                {1}
            </saml2p:Response>";

            var assertion1 = @"<saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_Validate_TrueOnCorrectSignedMultipleAssertionInResponseMessage_Assertion1""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>";

            var assertion2 = @"<saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_Validate_TrueOnCorrectSignedMultipleAssertionInResponseMessage_Assertion2""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser2</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>";


            var signedAssertion1 = SignedXmlHelper.SignXml(assertion1);
            var signedAssertion2 = SignedXmlHelper.SignXml(assertion2);
            var signedResponse = string.Format(response, signedAssertion1, signedAssertion2);

            Saml2Response.Read(signedResponse).Validate(SignedXmlHelper.TestCert).Should().BeTrue();
        }

        [TestMethod]
        public void Saml2Response_Validate_FalseOnMultipleAssertionInUnsignedResponseMessageButNotAllSigned()
        {
            var response =
            @"<saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            ID = ""Saml2Response_Validate_FalseOnMultipleAssertionInUnsignedResponseMessageButNotAllSigned"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z""
            Issuer = ""https://some.issuer.example.com"">
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Requester"" />
                </saml2p:Status>
                {0}
                {1}
            </saml2p:Response>";

            var assertion1 = @"<saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_Validate_FalseOnMultipleAssertionInUnsignedResponseMessageButNotAllSigned_Assertion1""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>";

            var assertion2 = @"<saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_Validate_FalseOnMultipleAssertionInUnsignedResponseMessageButNotAllSigned_Assertion2""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser2</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>";


            var signedAssertion1 = SignedXmlHelper.SignXml(assertion1);
            var signedResponse = string.Format(response, signedAssertion1, assertion2);

            Saml2Response.Read(signedResponse).Validate(SignedXmlHelper.TestCert).Should().BeFalse();
        }

        [TestMethod]
        public void Saml2Response_Validate_FalseOnTamperedMessage()
        {
            var response =
            @"<saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            ID = ""Saml2Response_Validate_FalseOnTamperedMessage"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z""
            Issuer = ""https://some.issuer.example.com"">
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Requester"" />
                </saml2p:Status>
            </saml2p:Response>";

            var signedResponse = SignedXmlHelper.SignXml(response);

            signedResponse = signedResponse.Replace("2013-01-01", "2013-01-02");

            Saml2Response.Read(signedResponse).Validate(SignedXmlHelper.TestCert).Should().BeFalse();
        }

        [TestMethod]
        public void Saml2Response_Validate_FalseOnTamperedAssertionWithMessageSignature()
        {
            var response =
            @"<saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            ID = ""Saml2Response_Validate_FalseOnTamperedAssertionWithMessageSignature"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z""
            Issuer = ""https://some.issuer.example.com"">
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Requester"" />
                </saml2p:Status>
                <saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_Validate_FalseOnTamperedAssertionWithMessageSignature_Assertion1""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>
            </saml2p:Response>";

            var signedResponse = SignedXmlHelper.SignXml(response).Replace("SomeUser", "SomeOtherUser");

            Saml2Response.Read(signedResponse).Validate(SignedXmlHelper.TestCert).Should().BeFalse();
        }

        [TestMethod]
        public void Saml2Response_Validate_FalseOnTamperedAssertionWithAssertionSignature()
        {
            var response =
            @"<saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            ID = ""Saml2Response_Validate_FalseOnTamperedAssertionWithAssertionSignature"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z""
            Issuer = ""https://some.issuer.example.com"">
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Requester"" />
                </saml2p:Status>
                {0}
                {1}
            </saml2p:Response>";

            var assertion1 = @"<saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_Validate_FalseOnTamperedAssertionWithAssertionSignature_Assertion1""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>";

            var assertion2 = @"<saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_Validate_FalseOnTamperedAssertionWithAssertionSignature_Assertion2""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser2</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>";

            var signedAssertion1 = SignedXmlHelper.SignXml(assertion1);
            var signedAssertion2 = SignedXmlHelper.SignXml(assertion2).Replace("SomeUser2", "SomeOtherUser");
            var signedResponse = string.Format(response, signedAssertion1, signedAssertion2);

            Saml2Response.Read(signedResponse).Validate(SignedXmlHelper.TestCert).Should().BeFalse();
        }

        [TestMethod]
        public void Saml2Response_Validate_FalseOnAssertionInjectionWithAssertionSignature()
        {
            var response =
            @"<saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            ID = ""Saml2Response_Validate_FalseOnAssertionInjectionWithAssertionSignature"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z""
            Issuer = ""https://some.issuer.example.com"">
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Requester"" />
                </saml2p:Status>
                {0}
                {1}
            </saml2p:Response>";

            var assertion1 = @"<saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_Validate_FalseOnAssertionInjectionWithAssertionSignature_Assertion1""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>";

            var assertionToInject = @"<saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_Validate_FalseOnAssertionInjectionWithAssertionSignature_Assertion2""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser2</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>";

            var signedAssertion1 = SignedXmlHelper.SignXml(assertion1);

            var signedAssertion1Doc = new XmlDocument { PreserveWhitespace = true };
            signedAssertion1Doc.LoadXml(signedAssertion1);

            var signatureToCopy = signedAssertion1Doc.DocumentElement["Signature", SignedXml.XmlDsigNamespaceUrl];

            var assertionToInjectDoc = new XmlDocument { PreserveWhitespace = true };
            assertionToInjectDoc.LoadXml(assertionToInject);

            assertionToInjectDoc.DocumentElement.AppendChild(assertionToInjectDoc.ImportNode(signatureToCopy, true));

            var signedAssertionToInject = assertionToInjectDoc.OuterXml;

            var signedResponse = string.Format(response, signedAssertion1, signedAssertionToInject);

            Saml2Response.Read(signedResponse).Validate(SignedXmlHelper.TestCert).Should().BeFalse();
        }

        [TestMethod]
        public void Saml2Response_Validate_ReturnsExistingResultOnSecondValidateCall()
        {
            var response =
            @"<saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            ID = ""Saml2Response_Validate_TrueOnCorrectSignedResponseMessage"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z""
            Issuer = ""https://some.issuer.example.com"">
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Requester"" />
                </saml2p:Status>
            </saml2p:Response>";

            var signedResponse = SignedXmlHelper.SignXml(response);

            var samlResponse = Saml2Response.Read(signedResponse);

            samlResponse.Validate(SignedXmlHelper.TestCert).Should().BeTrue();
            samlResponse.Validate(SignedXmlHelper.TestCert).Should().BeTrue();
        }

        [NotReRunnable]
        [TestMethod]
        public void Saml2Response_GetClaims_CreateIdentities()
        {
            var response =
            @"<?xml version=""1.0"" encoding=""UTF-8""?>
            <saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            ID = ""Saml2Response_GetClaims_CreateIdentities"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z""
            Issuer = ""https://some.issuer.example.com"">
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
                <saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_GetClaims_CreateIdentities1""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>
                <saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_GetClaims_CreateIdentities2""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeOtherUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>            
            </saml2p:Response>";

            var c1 = new ClaimsIdentity("Federation");
            c1.AddClaim(new Claim(ClaimTypes.NameIdentifier, "SomeUser", null, "https://idp.example.com"));
            var c2 = new ClaimsIdentity("Federation");
            c2.AddClaim(new Claim(ClaimTypes.NameIdentifier, "SomeOtherUser", null, "https://idp.example.com"));

            var expected = new ClaimsIdentity[] { c1, c2 };

            var r = Saml2Response.Read(SignedXmlHelper.SignXml(response));
            r.Validate(SignedXmlHelper.TestCert);

            r.GetClaims().ShouldBeEquivalentTo(expected, opt => opt.IgnoringCyclicReferences());
        }

        [TestMethod]
        public void Saml2Response_GetClaims_ThrowsOnNotValidated()
        {
            var response =
            @"<?xml version=""1.0"" encoding=""UTF-8""?>
            <saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            ID = ""Saml2Response_GetClaims_ThrowsOnNotValidated"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z""
            Issuer = ""https://some.issuer.example.com"">
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
                <saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_GetClaims_ThrowsOnNotValidated_Assertion""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                </saml2:Assertion>
            </saml2p:Response>";

            Action a = () => Saml2Response.Read(response).GetClaims();

            a.ShouldThrow<InvalidOperationException>()
                .WithMessage("The Saml2Response must be validated first.");

        }

        [TestMethod]
        public void Saml2Response_GetClaims_ThrowsOnResponseNotValid()
        {
            var response =
            @"<?xml version=""1.0"" encoding=""UTF-8""?>
            <saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            ID = ""Saml2Response_GetClaims_ThrowsOnResponseNotValid"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z""
            Issuer = ""https://some.issuer.example.com"">
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
                <saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_GetClaims_ThrowsOnResponseNotValid_Assertion""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                </saml2:Assertion>
            </saml2p:Response>";

            response = SignedXmlHelper.SignXml(response);
            response = response.Replace("2013-09-25", "2013-09-26");

            var r = Saml2Response.Read(response);
            r.Validate(SignedXmlHelper.TestCert);
            Action a = () => r.GetClaims();

            a.ShouldThrow<InvalidOperationException>()
                .WithMessage("The Saml2Response didn't pass validation");

            // Test that it throws again on subsequent calls.
            a.ShouldThrow<InvalidOperationException>()
                .WithMessage("The Saml2Response didn't pass validation");
        }

        [NotReRunnable]
        [TestMethod]
        public void Saml2Response_GetClaims_ThrowsOnWrongAudience()
        {
            var response =
            @"<?xml version=""1.0"" encoding=""UTF-8""?>
            <saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            ID = ""Saml2Response_GetClaims_ThrowsOnWrongAudience"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z""
            Issuer = ""https://some.issuer.example.com"">
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
                <saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_GetClaims_ThrowsOnWrongAudience_Assertion""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" >
                        <saml2:AudienceRestriction>
                            <saml2:Audience>https://example.com/wrong/audience</saml2:Audience>
                        </saml2:AudienceRestriction>
                    </saml2:Conditions>
                </saml2:Assertion>
            </saml2p:Response>";

            response = SignedXmlHelper.SignXml(response);

            var r = Saml2Response.Read(response);
            r.Validate(SignedXmlHelper.TestCert);

            Action a = () => r.GetClaims();

            a.ShouldThrow<AudienceUriValidationFailedException>();
        }

        [TestMethod]
        public void Saml2Response_GetClaims_ThrowsOnExpired()
        {
            var response =
            @"<?xml version=""1.0"" encoding=""UTF-8""?>
            <saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            ID = ""Saml2Response_GetClaims_ThrowsOnExpired"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z""
            Issuer = ""https://some.issuer.example.com"">
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
                <saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_GetClaims_ThrowsOnExpired_Assertion""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2013-06-30T08:00:00Z"" />
                </saml2:Assertion>
            </saml2p:Response>";

            response = SignedXmlHelper.SignXml(response);
            var r = Saml2Response.Read(response);
            r.Validate(SignedXmlHelper.TestCert);

            Action a = () => r.GetClaims();

            a.ShouldThrow<SecurityTokenExpiredException>();
        }

        [TestMethod]
        [Ignore]
        public void Saml2Response_Validate_FalseOnInvalidInResponseTo()
        {
        }

        [TestMethod]
        [Ignore]
        public void Saml2Response_Validate_FalseOnSecondInResponseTo()
        {
        }

        [TestMethod]
        [NotReRunnable]
        public void Saml2Response_GetClaims_ThrowsOnReplayAssertionId()
        {
            var response =
            @"<?xml version=""1.0"" encoding=""UTF-8""?>
            <saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            ID = ""Saml2Response_GetClaims_ThrowsOnReplayAssertionId"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z""
            Issuer = ""https://some.issuer.example.com"">
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
                <saml2:Assertion xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                Version=""2.0"" ID=""Saml2Response_GetClaims_ThrowsOnReplayAssertionId_Assertion""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>
            </saml2p:Response>";

            response = SignedXmlHelper.SignXml(response);
            var r1 = Saml2Response.Read(response);
            r1.Validate(SignedXmlHelper.TestCert).Should().BeTrue();
            r1.GetClaims();

            var r2 = Saml2Response.Read(response);
            r2.Validate(SignedXmlHelper.TestCert).Should().BeTrue();

            Action a = () => r2.GetClaims();

            a.ShouldThrow<SecurityTokenReplayDetectedException>();
        }

        [TestMethod]
        [Ignore]
        public void Saml2Response_Validate_FalseOnIncorrectInResponseTo()
        {
        }

        [TestMethod]
        public void Saml2Response_Ctor_FromData()
        {
            var issuer = "http://idp.example.com";
            var identity = new ClaimsIdentity(new Claim[] 
            {
                new Claim(ClaimTypes.NameIdentifier, "JohnDoe") 
            });
            var response = new Saml2Response(issuer, null, null, identity);

            response.Issuer.Should().Be(issuer);
            response.GetClaims().Single().ShouldBeEquivalentTo(identity);
        }

        [TestMethod]
        public void Saml2Response_Xml_FromData_ContainsBasicData()
        {
            var issuer = "http://idp.example.com";
            var nameId = "JohnDoe";
            var destination= "http://destination.example.com/";

            var identity = new ClaimsIdentity(new Claim[] 
            {
                new Claim(ClaimTypes.NameIdentifier, nameId) 
            });

            // Grab current time both before and after generating the response
            // to avoid heisenbugs if the second counter is updated while creating
            // the response.
            string before = DateTime.UtcNow.ToString("s") + "Z";
            var response = new Saml2Response(issuer, SignedXmlHelper.TestCert, 
                new Uri(destination), identity);
            string after = DateTime.UtcNow.ToString("s") + "Z";

            var xml = response.XmlDocument;

            xml.FirstChild.OuterXml.Should().StartWith("<?xml version=\"1.0\"");
            xml.DocumentElement["Issuer", Saml2Namespaces.Saml2Name].InnerText.Should().Be(issuer);
            xml.DocumentElement["Assertion", Saml2Namespaces.Saml2Name]
                ["Subject", Saml2Namespaces.Saml2Name]["NameID", Saml2Namespaces.Saml2Name]
                .InnerText.Should().Be(nameId);
            xml.DocumentElement.GetAttribute("Destination").Should().Be(destination);
            xml.DocumentElement.GetAttribute("ID").Should().NotBeBlank();
            xml.DocumentElement.GetAttribute("Version").Should().Be("2.0");
            xml.DocumentElement.GetAttribute("IssueInstant").Should().Match(
                i => i == before || i == after);
        }

        [TestMethod]
        public void Saml2Response_Xml_FromData_ContainsStatus_Success()
        {
            var identity = new ClaimsIdentity(new Claim[] 
            {
                new Claim(ClaimTypes.NameIdentifier, "JohnDoe") 
            });

            var response = new Saml2Response("issuer", SignedXmlHelper.TestCert,
                new Uri("http://destination.example.com"), identity);

            var xml = response.XmlDocument;

            var subject = xml.DocumentElement["Status", Saml2Namespaces.Saml2PName];

            subject["StatusCode", Saml2Namespaces.Saml2PName].GetAttribute("Value")
                .Should().Be("urn:oasis:names:tc:SAML:2.0:status:Success");
        }

        [TestMethod]
        public void Saml2Response_Xml_FromData_IsSigned()
        {
            var issuer = "http://idp.example.com";
            var nameId = "JohnDoe";
            var identity = new ClaimsIdentity(new Claim[] 
            {
                new Claim(ClaimTypes.NameIdentifier, nameId) 
            });

            var response = new Saml2Response(issuer, SignedXmlHelper.TestCert, 
                null, claimsIdentities: identity);

            var xml = response.XmlDocument;

            var signedXml = new SignedXml(xml);
            var signature = xml.DocumentElement["Signature", SignedXml.XmlDsigNamespaceUrl];
            signedXml.LoadXml(signature);

            signature.Should().NotBeNull();

            signedXml.CheckSignature(SignedXmlHelper.TestCert, true).Should().BeTrue();
        }

        [TestMethod]
        public void Saml2Response_ToXml()
        {
            string response = @"<?xml version=""1.0"" encoding=""UTF-8""?><saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol"" ID=""Saml2Response_ToXml"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z""><saml2p:Status><saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Requester"" /></saml2p:Status></saml2p:Response>";
            
            var subject = Saml2Response.Read(response).ToXml();

            subject.Should().Be(response);
        }

        [TestMethod]
        public void Saml2Response_MessageName()
        {
            var subject = new Saml2Response("issuer", null, null);

            subject.MessageName.Should().Be("SAMLResponse");
        }
    }
}
