﻿using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using FluentAssertions;
using System.Xml.Linq;
using System.IdentityModel.Tokens;
using System.Xml;
using Kentor.AuthServices.Saml2P;

namespace Kentor.AuthServices.Tests.Saml2P
{
    [TestClass]
    public class Saml2AuthenticationRequestTests
    {
        [TestMethod]
        public void Saml2AuthenticationRequest_ToXElement_RootNode()
        {
            var subject = new Saml2AuthenticationRequest().ToXElement();

            subject.Should().NotBeNull().And.Subject.Name.Should().Be(
                Saml2Namespaces.Saml2P + "AuthnRequest");
        }

        [TestMethod]
        public void Saml2AuthenticationRequest_ToXElement_AddsRequestBaseFields()
        {
            // Just checking for the id field and assuming that means that the
            // base fields are added. The details of the fields are tested
            // by Saml2RequestBaseTests.

            var subject = new Saml2AuthenticationRequest().ToXElement();

            subject.Should().NotBeNull().And.Subject.Attribute("ID").Should().NotBeNull();
            subject.Attribute("AttributeConsumingServiceIndex").Should().BeNull();
        }

        [TestMethod]
        public void Saml2AuthenticationRequest_ToXElement_AddsAttributeConsumingServiceIndex()
        {
            var subject = new Saml2AuthenticationRequest()
            {
                AttributeConsumingServiceIndex = 17
            }.ToXElement();

            subject.Attribute("AttributeConsumingServiceIndex").Value.Should().Be("17");
        }

        [TestMethod]
        public void Saml2AuthenticationRequest_AssertionConsumerServiceUrl()
        {
            string url = "http://some.example.com/Saml2AuthenticationModule/acs";
            var subject = new Saml2AuthenticationRequest()
            {
                AssertionConsumerServiceUrl = new Uri(url)
            }.ToXElement();

            subject.Should().NotBeNull().And.Subject.Attribute("AssertionConsumerServiceURL")
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

            var relayState = "My relay state";

            var subject = Saml2AuthenticationRequest.Read(xmlData, relayState);

            subject.Id.Should().Be(new Saml2Id("Saml2AuthenticationRequest_AssertionConsumerServiceUrl"));
            subject.AssertionConsumerServiceUrl.Should().Be(new Uri("https://sp.example.com/SAML2/Acs"));
            subject.RelayState.Should().Be(relayState);
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

            var subject = Saml2AuthenticationRequest.Read(xmlData, null);

            subject.Id.Should().Be(new Saml2Id("Saml2AuthenticationRequest_Read_NoACS"));
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

            Action a = () => Saml2AuthenticationRequest.Read(xmlData, null);

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

            Action a = () => Saml2AuthenticationRequest.Read(xmlData, null);

            a.ShouldThrow<XmlException>().WithMessage("Expected a SAML2 authentication request document");
        }

        [TestMethod]
        public void Saml2AuthenticationRequest_Read_NameIdPolicy()
        {
            var xmlData = @"<?xml version=""1.0"" encoding=""UTF-8""?>
<saml2p:AuthnRequest xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
                     xmlns:saml2 =""urn:oasis:names:tc:SAML:2.0:assertion""
                     ID=""ide3c2f1c88255463ab4eb1b158fa6f616""
                     Version=""2.0""
                     IssueInstant=""2016-01-25T13:01:09Z""
                     Destination=""http://destination.example.com""
                     AssertionConsumerServiceURL=""https://sp.example.com/SAML2/Acs""
                     >
    <saml2:Issuer>https://sp.example.com/SAML2</saml2:Issuer>
    <saml2p:NameIDPolicy AllowCreate = ""0"" Format = ""urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"" />
   </saml2p:AuthnRequest>";

            var subject = Saml2AuthenticationRequest.Read(xmlData, null);
            subject.NameIdPolicy.AllowCreate.Should().Be(false);
            subject.NameIdPolicy.Format.Should().Be(NameIdFormat.Persistent);
        }

        [TestMethod]
        public void Saml2AuthenticationRequest_Read_NoFormat()
        {
            var xmlData = @"<?xml version=""1.0"" encoding=""UTF-8""?>
<saml2p:AuthnRequest xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
                     xmlns:saml2 =""urn:oasis:names:tc:SAML:2.0:assertion""
                     ID=""ide3c2f1c88255463ab4eb1b158fa6f616""
                     Version=""2.0""
                     IssueInstant=""2016-01-25T13:01:09Z""
                     Destination=""http://destination.example.com""
                     AssertionConsumerServiceURL=""https://sp.example.com/SAML2/Acs""
                     >
    <saml2:Issuer>https://sp.example.com/SAML2</saml2:Issuer>
    <saml2p:NameIDPolicy AllowCreate = ""0""/>
   </saml2p:AuthnRequest>";

            var subject = Saml2AuthenticationRequest.Read(xmlData, null);
            subject.NameIdPolicy.AllowCreate.Should().Be(false);
            subject.NameIdPolicy.Format.Should().Be(NameIdFormat.Transient);
        }

        [TestMethod]
        public void Saml2AuthenticationRequest_ToXElement_AddsElementSaml2NameIdPolicy()
        {
            var subject = new Saml2AuthenticationRequest()
            {
                AssertionConsumerServiceUrl = new Uri("http://destination.example.com"),
                NameIdPolicy = new Saml2NameIdPolicy { AllowCreate = false, Format = NameIdFormat.EmailAddress}
            }.ToXElement();

            XNamespace ns = "urn:oasis:names:tc:SAML:2.0:protocol";
            subject.Attribute("AttributeConsumingServiceIndex").Should().BeNull();
            subject.Should().NotBeNull().And.Subject.Element(ns + "NameIDPolicy").Should().NotBeNull();
        }

        [TestMethod]
        public void Saml2AuthenticationRequest_Read_ShouldReturnNullOnNullXml()
        {
            string xmlData = null;

            var subject = Saml2AuthenticationRequest.Read(xmlData, null);

            subject.Should().BeNull();
        }
    }
}
