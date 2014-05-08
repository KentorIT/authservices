﻿using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using FluentAssertions;
using System.Net;
using System.Web;
using NSubstitute;
using System.Collections.Specialized;
using System.Text;
using System.Security.Claims;
using System.Xml;

namespace Kentor.AuthServices.Tests
{
    using System.IdentityModel.Tokens;

    [TestClass]
    public class AcsCommandTests
    {
        [TestMethod]
        public void AcsCommand_Run_ErrorOnNoSamlResponseFound()
        {
            Action a = () => new AcsCommand().Run(Substitute.For<HttpRequestBase>());

            a.ShouldThrow<NoSamlResponseFoundException>()
                .WithMessage("No Saml2 Response found in the http request.");
        }

        [TestMethod]
        public void AcsCommand_Run_ErrorOnNotBase64InFormResponse()
        {
            var r = Substitute.For<HttpRequestBase>();
            r.HttpMethod.Returns("POST");
            r.Form.Returns(new NameValueCollection() { { "SAMLResponse", "#¤!2" } });

            Action a = () => new AcsCommand().Run(r);

            a.ShouldThrow<BadFormatSamlResponseException>()
                .WithMessage("The SAML Response did not contain valid BASE64 encoded data.")
                .WithInnerException<FormatException>();
        }

        [TestMethod]
        public void AcsCommand_Run_ErrorOnIncorrectXml()
        {
            var r = Substitute.For<HttpRequestBase>();
            r.HttpMethod.Returns("POST");
            var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes("<foo />"));
            r.Form.Returns(new NameValueCollection() { { "SAMLResponse", encoded } });

            Action a = () => new AcsCommand().Run(r);

            a.ShouldThrow<BadFormatSamlResponseException>()
                .WithMessage("The SAML response contains incorrect XML")
                .WithInnerException<XmlException>();
        }

        [TestMethod]
        [NotReRunnable]
        public void AcsCommand_Run_SuccessfulResult()
        {
            var r = Substitute.For<HttpRequestBase>();
            r.HttpMethod.Returns("POST");

            var response =
            @"<saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
                xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
                ID = ""AcsCommand_Run_SuccessfulResult"" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z"">
                <saml2:Issuer>
                    https://idp.example.com
                </saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
                <saml2:Assertion
                Version=""2.0"" ID=""Saml2Response_GetClaims_CreateIdentity_Assertion1""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>
            </saml2p:Response>";

            var formValue = Convert.ToBase64String(Encoding.UTF8.GetBytes(
                SignedXmlHelper.SignXml(response)));

            r.Form.Returns(new NameValueCollection() { { "SAMLResponse", formValue } });

            var ids = new ClaimsIdentity[]
                { new ClaimsIdentity("Federation"), new ClaimsIdentity("ClaimsAuthenticationManager") };
            ids[0].AddClaim(new Claim(ClaimTypes.NameIdentifier, "SomeUser", null, "https://idp.example.com"));
            ids[1].AddClaim(new Claim(ClaimTypes.Role, "RoleFromClaimsAuthManager", null, "ClaimsAuthenticationManagerMock"));
            
            SecurityToken token;
            var document = new XmlDocument();
            document.LoadXml(response);
            using (var reader = new XmlNodeReader(document.DocumentElement["saml2:Assertion"]))
            {
                token = MorePublicSaml2SecurityTokenHandler.DefaultInstance.ReadToken(reader);
            }

            var expected = new CommandResult()
                                   {
                                       Principal = new ClaimsPrincipal(ids),
                                       HttpStatusCode = HttpStatusCode.SeeOther,
                                       Location = new Uri("http://localhost/LoggedIn"),
                                       SecurityTokens = new[] { token }
                                   };
            

            new AcsCommand().Run(r).ShouldBeEquivalentTo(expected,
                opt => opt.IgnoringCyclicReferences());
        }
    }
}
