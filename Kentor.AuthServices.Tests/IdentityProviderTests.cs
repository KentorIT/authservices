﻿using System;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using FluentAssertions;
using Kentor.AuthServices.TestHelpers;
using Kentor.AuthServices.Configuration;
using System.Configuration;
using System.IdentityModel.Metadata;
using System.Collections.Generic;

namespace Kentor.AuthServices.Tests
{
    [TestClass]
    public class IdentityProviderTests
    {
        [TestMethod]
        public void IdentityProvider_CreateAuthenticateRequest_Destination()
        {
            string idpUri = "http://idp.example.com/";
            
            var ip = new IdentityProvider(new Uri(idpUri));

            var r = ip.CreateAuthenticateRequest(null);

            r.ToXElement().Attribute("Destination").Should().NotBeNull()
                .And.Subject.Value.Should().Be(idpUri);
        }

        [TestMethod]
        public void IdentityProvider_CreateAuthenticateRequest_AssertionConsumerServiceUrlFromConfig()
        {
            var idp = IdentityProvider.ActiveIdentityProviders.First();

            var r = idp.CreateAuthenticateRequest(null);

            r.AssertionConsumerServiceUrl.Should().Be(new Uri("http://localhost/Saml2AuthenticationModule/acs"));
        }

        [TestMethod]
        public void IdentityProvider_CreateAuthenticateRequest_IssuerFromConfig()
        {
            var idp = IdentityProvider.ActiveIdentityProviders.First();

            var r = idp.CreateAuthenticateRequest(null);

            r.Issuer.Should().Be("https://github.com/KentorIT/authservices");
        }

        [TestMethod]
        public void IdentityProvider_Certificate_FromFile()
        {
            var idp = IdentityProvider.ActiveIdentityProviders.First();

            idp.SigningKey.ShouldBeEquivalentTo(SignedXmlHelper.TestKey);
        }

        [TestMethod]
        public void IdentityProvider_AllowUnsolicitedAuthnResponse_FromConfig()
        {
            IdentityProvider.ActiveIdentityProviders[new EntityId("https://idp.example.com")]
                .AllowUnsolicitedAuthnResponse.Should().BeTrue();

            IdentityProvider.ActiveIdentityProviders[new EntityId("https://idp2.example.com")]
                .AllowUnsolicitedAuthnResponse.Should().BeFalse();
        }

        [TestMethod]
        public void IdentityProvider_AllowUnsolicitedAuthnResponse_FromConfigForFederation()
        {
            IdentityProvider.ActiveIdentityProviders[new EntityId("http://idp.federation.example.com/metadata")]
                .AllowUnsolicitedAuthnResponse.Should().BeTrue();
        }

        [TestMethod]
        public void IdentityProvider_ConfigFromMetadata()
        {
            var entityId = new EntityId("http://localhost:13428/idpMetadata");
            var idpFromMetadata = IdentityProvider.ActiveIdentityProviders[entityId];

            idpFromMetadata.EntityId.Id.Should().Be(entityId.Id);
            idpFromMetadata.Binding.Should().Be(Saml2BindingType.HttpPost);
            idpFromMetadata.AssertionConsumerServiceUrl.Should().Be(new Uri("http://localhost:13428/acs"));
            idpFromMetadata.SigningKey.ShouldBeEquivalentTo(SignedXmlHelper.TestKey);
        }

        [TestMethod]
        public void IdentityProvider_FederationManagerLoads()
        {
            var entityId = new EntityId("http://idp.test.com/metadata1");
            var idpFromMetadata = IdentityProvider.ActiveIdentityProviders[entityId];

            idpFromMetadata.EntityId.Id.Should().Be(entityId.Id);
            idpFromMetadata.Binding.Should().Be(Saml2BindingType.HttpRedirect);
            idpFromMetadata.AssertionConsumerServiceUrl.Should().Be(new Uri("http://idp.test.com"));
            idpFromMetadata.SigningKey.ShouldBeEquivalentTo(SignedXmlHelper.TestKey);
        }

        [TestMethod]
        public void IdentityProvider_FederationManagerReload()
        {
            // Reset manually using test hook
            IdentityProvider.ActiveIdentityProvidersMap.lastFederationLoad = DateTime.MinValue;
            TestFederationManager.NumberOfEntries = 1;

            var startingCount = IdentityProvider.ActiveIdentityProviders.Count();
            TestFederationManager.NumberOfEntries = 2;

            // Not enough time since last should have elapsed. Value should remain the same.
            IdentityProvider.ActiveIdentityProviders.Count().Should().Be(startingCount);

            // Reset manually using test hook
            IdentityProvider.ActiveIdentityProvidersMap.lastFederationLoad = DateTime.MinValue;
            var count = IdentityProvider.ActiveIdentityProviders.Count();
            count.Should().Be(startingCount + 1);
        }

        private IdentityProviderElement CreateConfig()
        {
            var config = new IdentityProviderElement();
            config.AllowConfigEdit(true);
            config.Binding = Saml2BindingType.HttpPost;
            config.SigningCertificate = new CertificateElement();
            config.SigningCertificate.AllowConfigEdit(true);
            config.SigningCertificate.FileName = "Kentor.AuthServices.Tests.pfx";
            config.DestinationUri = new Uri("http://idp.example.com/acs");
            config.EntityId = "http://idp.example.com";

            return config;
        }

        private static void TestMissingConfig(IdentityProviderElement config, string missingElement)
        {
            Action a = () => new IdentityProvider(config);

            string expectedMessage = "Missing " + missingElement + " configuration on Idp " + config.EntityId + ".";
            a.ShouldThrow<ConfigurationErrorsException>(expectedMessage);
        }

        [TestMethod]
        public void IdentityProvider_Ctor_MissingBindingThrows()
        {
            var config = CreateConfig();
            config.Binding = 0;
            TestMissingConfig(config, "binding");
        }

        [TestMethod]
        public void IdentityProvider_Ctor_MissingCertificateThrows()
        {
            var config = CreateConfig();
            
            // Don't set to null; if the section isn't present in the config the
            // loaded configuration will contain an empty SigningCertificate element.
            config.SigningCertificate = new CertificateElement();
            TestMissingConfig(config, "signing certificate");
        }

        [TestMethod]
        public void IdentityProvider_Ctor_MissingDestinationUriThrows()
        {
            var config = CreateConfig();
            config.DestinationUri = null;
            TestMissingConfig(config, "assertion consumer service url");
        }

        [TestMethod]
        public void IdentityProvider_Ctor_HandlesConfiguredCertificateWhenReadingMetadata()
        {
            var config = CreateConfig();
            config.LoadMetadata = true;
            config.EntityId = "http://localhost:13428/idpMetadataNoCertificate";

            var subject = new IdentityProvider(config);

            // Check that metadata was read and overrides configured values.
            subject.Binding.Should().Be(Saml2BindingType.HttpRedirect);
            subject.SigningKey.ShouldBeEquivalentTo(SignedXmlHelper.TestKey);
        }

        [TestMethod]
        public void IdentityProvider_Ctor_WrongEntityIdInMetadata()
        {
            var config = CreateConfig();
            config.LoadMetadata = true;
            config.EntityId = "http://localhost:13428/idpMetadataWrongEntityId";

            Action a = () => new IdentityProvider(config);

            a.ShouldThrow<ConfigurationErrorsException>().And.Message.Should()
                .Be("Unexpected entity id \"http://wrong.entityid.example.com\" found when loading metadata for \"http://localhost:13428/idpMetadataWrongEntityId\".");
        }

        [TestMethod]
        public void IdentityProvider_ActiveIdentityProviders_IncludeIdpFromFederation()
        {
            var subject = IdentityProvider.ActiveIdentityProviders[
                new EntityId("http://idp.federation.example.com/metadata")];

            subject.EntityId.Id.Should().Be("http://idp.federation.example.com/metadata");
            subject.Binding.Should().Be(Saml2BindingType.HttpRedirect);
        }

        [TestMethod]
        public void IdentityProvider_ActiveIdentityProviders_ThrowsOnInvalidEntityId()
        {
            Action a = () => { 
                var i = IdentityProvider.ActiveIdentityProviders[
                new EntityId("urn:Non.Existent.EntityId")];
            };

            a.ShouldThrow<KeyNotFoundException>().And.Message.Should().Be("No Idp with entity id \"urn:Non.Existent.EntityId\" found.");
        }

        [TestMethod]
        public void IdentityProvider_ActiveIdentityProviders_EnumerationIncludesFederationIdps()
        {
            IdentityProvider.ActiveIdentityProviders.Select(idp => idp.EntityId.Id)
                .Should().Contain("http://idp.federation.example.com/metadata");
        }
    }
}
