﻿using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using FluentAssertions;
using System.Xml.Linq;
using System.IdentityModel.Tokens;
using System.Xml;

namespace Kentor.AuthServices.Tests
{
    [TestClass]
    public class Saml2AuthenticationRequestTests
    {
        [TestMethod]
        public void Saml2AuthenticationRequest_ToXElement_RootNode()
        {
            var x = new Saml2AuthenticationRequest().ToXElement();

            x.Should().NotBeNull().And.Subject.Name.Should().Be(
                Saml2Namespaces.Saml2P + "AuthnRequest");
        }

        [TestMethod]
        public void Saml2AuthenticationRequest_ToXElement_AddsRequestBaseFields()
        {
            // Just checking for the id field and assuming that means that the
            // base fields are added. The details of the fields are tested
            // by Saml2RequestBaseTests.

            var x = new Saml2AuthenticationRequest().ToXElement();

            x.Should().NotBeNull().And.Subject.Attribute("ID").Should().NotBeNull();
        }

        [TestMethod]
        public void Saml2AuthenticationRequest_AssertionConsumerServiceUrl()
        {
            string url = "http://some.example.com/AuthServices/acs";
            var x = new Saml2AuthenticationRequest() 
            {
                AssertionConsumerServiceUrl = new Uri(url)
            }.ToXElement();

            x.Should().NotBeNull().And.Subject.Attribute("AssertionConsumerServiceURL")
                .Should().NotBeNull().And.Subject.Value.Should().Be(url);
        }

        [TestMethod]
        public void Saml2AuthenticationRequest_Read()
        {
            var xmlData = @"<?xml version=""1.0"" encoding=""UTF-8""?>
<samlp:AuthnRequest
  xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol""
  xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion""
  ID=""Saml2AuthenticationRequest_AssertionConsumerServiceUrl""
  Version=""2.0""
  Destination=""http://destination.example.com""
  AssertionConsumerServiceURL=""https://sp.example.com/SAML2/Acs""
  IssueInstant=""2004-12-05T09:21:59Z"">
  <saml:Issuer>https://sp.example.com/SAML2</saml:Issuer>
/>
</samlp:AuthnRequest>
";

            var subject = Saml2AuthenticationRequest.Read(xmlData);

            subject.Id.Should().Be("Saml2AuthenticationRequest_AssertionConsumerServiceUrl");
            subject.AssertionConsumerServiceUrl.Should().Be(new Uri("https://sp.example.com/SAML2/Acs"));
        }

        [TestMethod]
        public void Saml2AuthenticationRequest_Read_NoACS()
        {
            var xmlData = @"<?xml version=""1.0"" encoding=""UTF-8""?>
<samlp:AuthnRequest
  xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol""
  xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion""
  ID=""Saml2AuthenticationRequest_Read_NoACS""
  Version=""2.0""
  Destination=""http://destination.example.com""
  IssueInstant=""2004-12-05T09:21:59Z"">
  <saml:Issuer>https://sp.example.com/SAML2</saml:Issuer>
/>
</samlp:AuthnRequest>
";

            var subject = Saml2AuthenticationRequest.Read(xmlData);

            subject.Id.Should().Be("Saml2AuthenticationRequest_Read_NoACS");
            subject.AssertionConsumerServiceUrl.Should().Be(null);
        }

        [TestMethod]
        public void Saml2AuthenticationRequest_Read_ShouldThrowOnInvalidVersion()
        {
            var xmlData = @"<?xml version=""1.0"" encoding=""UTF-8""?>
<samlp:AuthnRequest
  xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol""
  xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion""
  ID=""Saml2AuthenticationRequest_Read_ShouldThrowOnInvalidVersion""
  Version=""123456789.0""
  Destination=""http://destination.example.com""
  AssertionConsumerServiceURL=""https://sp.example.com/SAML2/Acs""
  IssueInstant=""2004-12-05T09:21:59Z""
  InResponseTo=""111222333"">
  <saml:Issuer>https://sp.example.com/SAML2</saml:Issuer>
/>
</samlp:AuthnRequest>
";

            Action a = () => Saml2AuthenticationRequest.Read(xmlData);

            a.ShouldThrow<XmlException>().WithMessage("Wrong or unsupported SAML2 version");
        }

        [TestMethod]
        public void Saml2AuthenticationRequest_Read_ShouldThrowOnInvalidMessageName()
        {
            var xmlData = @"<?xml version=""1.0"" encoding=""UTF-8""?>
<samlp:NotAuthnRequest
  xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol""
  xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion""
  ID=""Saml2AuthenticationRequest_Read_ShouldThrowOnInvalidMessageName""
  Version=""2.0""
  Destination=""http://destination.example.com""
  AssertionConsumerServiceURL=""https://sp.example.com/SAML2/Acs""
  IssueInstant=""2004-12-05T09:21:59Z""
  InResponseTo=""111222333"">
  <saml:Issuer>https://sp.example.com/SAML2</saml:Issuer>
/>
</samlp:NotAuthnRequest>
";

            Action a = () => Saml2AuthenticationRequest.Read(xmlData);

            a.ShouldThrow<XmlException>().WithMessage("Expected a SAML2 authentication request document");
        }

        [TestMethod]
        public void Saml2AuthenticationRequest_Read_ShouldReturnNullOnNullXml()
        {
            string xmlData = null;

            var subject = Saml2AuthenticationRequest.Read(xmlData);

            subject.Should().BeNull();
        }
    }
}
