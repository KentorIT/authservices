﻿using System.Linq;
using FluentAssertions;
using Kentor.AuthServices.Configuration;
using Kentor.AuthServices.Tests.Helpers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Configuration;
using System.IdentityModel.Metadata;
using Kentor.AuthServices.Saml2P;
using Kentor.AuthServices.WebSso;
using System.Net;
using Kentor.AuthServices.Tests.Metadata;
using Kentor.AuthServices.Metadata;
using System.Threading;
using System.Security.Cryptography;

namespace Kentor.AuthServices.Tests
{
    [TestClass]
    public class IdentityProviderTests
    {
        TimeSpan refreshMinInterval = MetadataRefreshScheduler.minInterval;
        int idpMetadataSsoPort = StubServer.IdpMetadataSsoPort;

        [TestCleanup]
        public void Cleanup()
        {
            StubServer.IdpMetadataSsoPort = idpMetadataSsoPort;
            StubServer.IdpVeryShortCacheDurationIncludeInvalidKey = false;
            StubServer.IdpVeryShortCacheDurationIncludeKey = true;
            MetadataRefreshScheduler.minInterval = refreshMinInterval;
        }

        [TestMethod]
        public void IdentityProvider_CreateAuthenticateRequest_DestinationInXml()
        {
            string idpUri = "http://idp.example.com/";

            var subject = new IdentityProvider(
                new EntityId(idpUri),
                Options.FromConfiguration.SPOptions)
                {
                    SingleSignOnServiceUrl = new Uri(idpUri)
                };

            var r = subject.CreateAuthenticateRequest(null, StubFactory.CreateAuthServicesUrls());

            r.ToXElement().Attribute("Destination").Should().NotBeNull()
                .And.Subject.Value.Should().Be(idpUri);
        }

        [TestMethod]
        public void IdentityProvider_CreateAuthenticateRequest_BasicInfo()
        {
            var options = Options.FromConfiguration;

            var idp = options.IdentityProviders.Default;

            var urls = StubFactory.CreateAuthServicesUrls();
            var subject = idp.CreateAuthenticateRequest(null, urls);

            var expected = new Saml2AuthenticationRequest()
            {
                AssertionConsumerServiceUrl = urls.AssertionConsumerServiceUrl,
                DestinationUrl = idp.SingleSignOnServiceUrl,
                Issuer = options.SPOptions.EntityId,
                AttributeConsumingServiceIndex = 0,
                NameIdPolicy = new Saml2NameIdPolicy {  AllowCreate = true, Format = NameIdFormat.EntityIdentifier}
            };

            subject.ShouldBeEquivalentTo(expected, opt => opt
            .Excluding(au => au.Id)
            .Excluding(au => au.RelayState));

            subject.RelayState.Should().HaveLength(56);
        }

        [TestMethod]
        public void IdentityProvider_CreateAuthenticateRequest_NoAttributeIndex()
        {
            var options = StubFactory.CreateOptions();
            var idp = options.IdentityProviders.Default;
            var urls = StubFactory.CreateAuthServicesUrls();

            ((SPOptions)options.SPOptions).AttributeConsumingServices.Clear();

            var subject = idp.CreateAuthenticateRequest(null, urls);

            var expected = new Saml2AuthenticationRequest()
            {
                AssertionConsumerServiceUrl = urls.AssertionConsumerServiceUrl,
                DestinationUrl = idp.SingleSignOnServiceUrl,
                Issuer = options.SPOptions.EntityId,
                AttributeConsumingServiceIndex = null
            };

            subject.ShouldBeEquivalentTo(expected, opt => opt
                .Excluding(au => au.Id)
                .Excluding(au => au.RelayState));
        }

        [TestMethod]
        public void IdentityProvider_CreateAuthenticateRequest_NullcheckAuthServicesUrls()
        {
            var idp = Options.FromConfiguration.IdentityProviders.Default;

            Action a = () => idp.CreateAuthenticateRequest(new Uri("http://localhost"), null);

            a.ShouldThrow<ArgumentNullException>().And.ParamName.Should().Be("authServicesUrls");
        }

        [TestMethod]
        public void IdentityProvider_CreateAuthenticateRequest_IncludesSigningCertificate()
        {
            var options = StubFactory.CreateOptions();
            var spOptions = (SPOptions)options.SPOptions;
            spOptions.AuthenticateRequestSigningBehavior = SigningBehavior.Always;
            spOptions.ServiceCertificates.Add(new ServiceCertificate
            {
                Certificate = SignedXmlHelper.TestCert
            });

            var idp = options.IdentityProviders.Default;
            var urls = StubFactory.CreateAuthServicesUrls();

            var subject = idp.CreateAuthenticateRequest(null, urls);

            subject.SigningCertificate.Thumbprint.Should().Be(SignedXmlHelper.TestCert.Thumbprint);
        }

        [TestMethod]
        public void IdentityProvider_CreateAuthenticateRequest_ThrowsOnMissingSigningCertificate()
        {
            var options = StubFactory.CreateOptions();
            var spOptions = (SPOptions)options.SPOptions;
            spOptions.AuthenticateRequestSigningBehavior = SigningBehavior.Always;

            var idp = options.IdentityProviders.Default;
            var urls = StubFactory.CreateAuthServicesUrls();

            idp.Invoking(i => i.CreateAuthenticateRequest(null, urls))
                .ShouldThrow<ConfigurationErrorsException>()
                .And.Message.Should().Be($"Idp \"https://idp.example.com\" is configured for signed AuthenticateRequests, but ServiceCertificates configuration contains no certificate with usage \"Signing\" or \"Both\".");
        }

        [TestMethod]
        public void IdentityProvider_Certificate_FromFile()
        {
            var idp = Options.FromConfiguration.IdentityProviders.Default;

            idp.SigningKeys.Single().ShouldBeEquivalentTo(SignedXmlHelper.TestKey);
        }

        [TestMethod]
        public void IdentityProvider_AllowUnsolicitedAuthnResponse_FromConfig()
        {
            Options.FromConfiguration.IdentityProviders[new EntityId("https://idp.example.com")]
                .AllowUnsolicitedAuthnResponse.Should().BeTrue();

            Options.FromConfiguration.IdentityProviders[new EntityId("https://idp2.example.com")]
                .AllowUnsolicitedAuthnResponse.Should().BeFalse();
        }

        [TestMethod]
        public void IdentityProvider_AllowUnsolicitedAuthnResponse_FromConfigForFederation()
        {
            Options.FromConfiguration.IdentityProviders[new EntityId("http://idp.federation.example.com/metadata")]
                .AllowUnsolicitedAuthnResponse.Should().BeTrue();
        }

        [TestMethod]
        public void IdentityProvider_ConfigFromMetadata()
        {
            var entityId = new EntityId("http://localhost:13428/idpMetadata");
            var subject = new IdentityProvider(entityId, StubFactory.CreateSPOptions());

            // Add one that will be removed by loading.
            subject.ArtifactResolutionServiceUrls.Add(234, new Uri("http://example.com"));

            subject.LoadMetadata = true;

            subject.EntityId.Id.Should().Be(entityId.Id);
            subject.Binding.Should().Be(Saml2BindingType.HttpPost);
            subject.SingleSignOnServiceUrl.Should().Be(new Uri("http://localhost:13428/acs"));
            subject.SigningKeys.Single().ShouldBeEquivalentTo(SignedXmlHelper.TestKey);
            subject.ArtifactResolutionServiceUrls.Count.Should().Be(2);
            subject.ArtifactResolutionServiceUrls[0x1234].OriginalString
                .Should().Be("http://localhost:13428/ars");
            subject.ArtifactResolutionServiceUrls[117].OriginalString
                .Should().Be("http://localhost:13428/ars2");
        }

        private IdentityProviderElement CreateConfig()
        {
            var config = new IdentityProviderElement();
            config.AllowConfigEdit(true);
            config.Binding = Saml2BindingType.HttpPost;
            config.SigningCertificate = new CertificateElement();
            config.SigningCertificate.AllowConfigEdit(true);
            config.SigningCertificate.FileName = "Kentor.AuthServices.Tests.pfx";
            config.DestinationUrl = new Uri("http://idp.example.com/acs");
            config.EntityId = "http://idp.example.com";

            return config;
        }

        private static void TestMissingConfig(IdentityProviderElement config, string missingElement)
        {
            Action a = () => new IdentityProvider(config, Options.FromConfiguration.SPOptions);

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
        public void IdentityProvider_Ctor_MissingDestinationUrlThrows()
        {
            var config = CreateConfig();
            config.DestinationUrl = null;
            TestMissingConfig(config, "assertion consumer service url");
        }

        [TestMethod]
        public void IdentityProvider_Ctor_HandlesConfiguredCertificateWhenReadingMetadata()
        {
            var config = CreateConfig();
            config.LoadMetadata = true;
            config.EntityId = "http://localhost:13428/idpMetadataNoCertificate";

            var subject = new IdentityProvider(config, Options.FromConfiguration.SPOptions);

            // Check that metadata was read and overrides configured values.
            subject.Binding.Should().Be(Saml2BindingType.HttpRedirect);
            subject.SigningKeys.Single().ShouldBeEquivalentTo(SignedXmlHelper.TestKey);
        }

        [TestMethod]
        public void IdentityProvider_Ctor_WrongEntityIdInMetadata()
        {
            var config = CreateConfig();
            config.LoadMetadata = true;
            config.EntityId = "http://localhost:13428/idpMetadataOtherEntityId";

            Action a = () => new IdentityProvider(config, Options.FromConfiguration.SPOptions);

            a.ShouldThrow<ConfigurationErrorsException>().And.Message.Should()
                .Be("Unexpected entity id \"http://other.entityid.example.com\" found when loading metadata for \"http://localhost:13428/idpMetadataOtherEntityId\".");
        }

        [TestMethod]
        public void IdentityProvider_Ctor_PrefersRedirectBindingFromMetadata()
        {
            var config = CreateConfig();
            config.LoadMetadata = true;
            config.EntityId = "http://localhost:13428/idpMetadataWithMultipleBindings";

            var subject = new IdentityProvider(config, Options.FromConfiguration.SPOptions);

            subject.Binding.Should().Be(Saml2BindingType.HttpRedirect);
            subject.SingleSignOnServiceUrl.Should().Be("http://idp2Bindings.example.com/Redirect");
        }

        [TestMethod]
        public void IdentityProvider_Ctor_ChoosesSupportedBindingFromMetadata()
        {
            var config = CreateConfig();
            config.LoadMetadata = true;
            config.EntityId = "http://localhost:13428/idpMetadataWithArtifactBinding";

            var subject = new IdentityProvider(config, Options.FromConfiguration.SPOptions);

            subject.Binding.Should().Be(Saml2BindingType.HttpPost);
            subject.SingleSignOnServiceUrl.Should().Be("http://idpArtifact.example.com/POST");
        }

        [TestMethod]
        public void IdentityProvider_Ctor_UseMetadataLocationUrl()
        {
            var config = CreateConfig();
            config.LoadMetadata = true;
            config.MetadataUrl = new Uri("http://localhost:13428/idpMetadataDifferentEntityId");
            config.EntityId = "some-idp";

            var subject = new IdentityProvider(config, Options.FromConfiguration.SPOptions);

            subject.Binding.Should().Be(Saml2BindingType.HttpRedirect);
            subject.SingleSignOnServiceUrl.Should().Be("http://idp.example.com/SsoService");
        }

        [TestMethod]
        public void IdentityProvider_MetadataValidUntil_NullOnConfigured()
        {
            string idpUri = "http://idp.example.com/";

            var subject = new IdentityProvider(
                new EntityId(idpUri),
                Options.FromConfiguration.SPOptions);

            subject.MetadataValidUntil.Should().NotHaveValue();
        }

        [TestMethod]
        public void IdentityProvider_MetadataValidUntil_Loaded()
        {
            var config = CreateConfig();
            config.LoadMetadata = true;
            config.EntityId = "http://localhost:13428/idpMetadata";

            var subject = new IdentityProvider(config, Options.FromConfiguration.SPOptions);

            subject.MetadataValidUntil.Should().Be(new DateTime(2100, 01, 02, 14, 42, 43, DateTimeKind.Utc));
        }

        [TestMethod]
        public void IdentityProvider_MetadataValidUntil_CalculatedFromCacheDuration()
        {
            var config = CreateConfig();
            config.LoadMetadata = true;
            config.EntityId = "http://localhost:13428/idpMetadataNoCertificate";

            var subject = new IdentityProvider(config, Options.FromConfiguration.SPOptions);

            var expectedValidUntil = DateTime.UtcNow.AddMinutes(15);
            // Comparison on the second is more than enough if we're adding 15 minutes.
            subject.MetadataValidUntil.Should().BeCloseTo(expectedValidUntil, 1000);
        }

        IdentityProvider CreateSubjectForMetadataRefresh()
        {
            var config = CreateConfig();
            config.LoadMetadata = true;
            config.EntityId = "http://localhost:13428/idpMetadataVeryShortCacheDuration";
            return new IdentityProvider(config, Options.FromConfiguration.SPOptions);
        }

        [TestMethod]
        public void IdentityProvier_CreateSubjectForMetadataRefresh()
        {
            // Had problems with the factory method causing exceptions, so this is a
            // meta test that ensures that the test harness is working.

            this.Invoking(i => i.CreateSubjectForMetadataRefresh()).ShouldNotThrow();
        }

        [TestMethod]
        public void IdentityProvider_Binding_ReloadsMetadataIfNoLongerValid()
        {
            StubServer.IdpVeryShortCacheDurationBinding = Saml2Binding.HttpRedirectUri;
            var subject = CreateSubjectForMetadataRefresh();
            subject.Binding.Should().Be(Saml2BindingType.HttpRedirect);
            StubServer.IdpVeryShortCacheDurationBinding = Saml2Binding.HttpPostUri;

            SpinWaiter.WhileEqual(() => subject.Binding, () => Saml2BindingType.HttpRedirect);

            subject.Binding.Should().Be(Saml2BindingType.HttpPost);
        }

        [TestMethod]
        public void IdentityProvider_SingleSignOnServiceUrl_ReloadsMetadataIfNoLongerValid()
        {
            StubServer.IdpAndFederationVeryShortCacheDurationPort = 42;
            var subject = CreateSubjectForMetadataRefresh();
            subject.SingleSignOnServiceUrl.Port.Should().Be(42);
            StubServer.IdpAndFederationVeryShortCacheDurationPort = 117;

            SpinWaiter.WhileEqual(() => subject.SingleSignOnServiceUrl.Port, () => 42);

            subject.SingleSignOnServiceUrl.Port.Should().Be(117);
        }


        [TestMethod]
        public void IdentityProvider_ArtifactResolutionServiceUrl_ReloadsMetadataIfNoLongerValid()
        {
            StubServer.IdpAndFederationVeryShortCacheDurationPort = 42;
            var subject = CreateSubjectForMetadataRefresh();
            subject.ArtifactResolutionServiceUrls[0].Port.Should().Be(42);
            StubServer.IdpAndFederationVeryShortCacheDurationPort = 117;

            SpinWaiter.WhileEqual(() => subject.ArtifactResolutionServiceUrls[0].Port, () => 42);

            subject.ArtifactResolutionServiceUrls[0].Port.Should().Be(117);
        }

        [TestMethod]
        public void IdentityProvider_SingleSignOnService_DoesntReloadMetadataIfStillValid()
        {
            var subject = new IdentityProvider(
                new EntityId("http://localhost:13428/idpMetadata"),
                StubFactory.CreateSPOptions())
                {
                    LoadMetadata = true
                };

            subject.SingleSignOnServiceUrl.Port.Should().Be(13428);
            StubServer.IdpMetadataSsoPort = 147;

            // Metadata shouldn't be reloaded so port shouldn't be changed.
            subject.SingleSignOnServiceUrl.Port.Should().Be(13428);
        }

        [TestMethod]
        public void IdentityProvider_SigningKeys_RemovesMetadataKeyButKeepsConfiguredKey()
        {
            var subject = CreateSubjectForMetadataRefresh();

            // One key from config, one key from metadata.
            subject.SigningKeys.Count().Should().Be(2);

            StubServer.IdpVeryShortCacheDurationIncludeKey = false;

            SpinWaiter.While(() => subject.SigningKeys.Count() == 2);

            var subjectKeyParams = subject.SigningKeys.Single().As<RSACryptoServiceProvider>().ExportParameters(false);
            var expectedKeyParams = SignedXmlHelper.TestKey.As<RSACryptoServiceProvider>().ExportParameters(false);

            subjectKeyParams.Modulus.ShouldBeEquivalentTo(expectedKeyParams.Modulus);
            subjectKeyParams.Exponent.ShouldBeEquivalentTo(expectedKeyParams.Exponent);
        }

        [TestMethod]
        public void IdentityProvider_SigningKeys_ReloadsMetadataIfNoLongerValid()
        {
            var subject = CreateSubjectForMetadataRefresh();
            subject.SigningKeys.LoadedItems.Should().NotBeEmpty();
            StubServer.IdpVeryShortCacheDurationIncludeInvalidKey = true;

            Action a = () =>
            {
                var waitStart = DateTime.UtcNow;
                while (subject.SigningKeys.LoadedItems.Any())
                {
                    if (DateTime.UtcNow - waitStart > SpinWaiter.MaxWait)
                    {
                        Assert.Fail("Timeout passed without metadata being refreshed.");
                    }
                }
            };

            a.ShouldThrow<System.Xml.XmlException>();
        }

        [TestMethod]
        public void IdentityProvider_ScheduledReloadOfMetadata()
        {
            MetadataRefreshScheduler.minInterval = new TimeSpan(0, 0, 0, 0, 1);

            var subject = CreateSubjectForMetadataRefresh();
            var initialValidUntil = subject.MetadataValidUntil;

            SpinWaiter.WhileEqual(() => subject.MetadataValidUntil, () => initialValidUntil);
        }

        [TestMethod]
        public void IdentityProvider_ScheduledReloadOfMetadata_RetriesIfLoadFails()
        {
            MetadataRefreshScheduler.minInterval = new TimeSpan(0, 0, 0, 0, 1);

            var subject = CreateSubjectForMetadataRefresh();

            StubServer.IdpAndFederationShortCacheDurationAvailable = false;

            SpinWaiter.While(() => subject.MetadataValidUntil != DateTime.MinValue,
                "Timed out waiting for failed metadata load to occur.");

            var metadataEnabledTime = DateTime.UtcNow;
            StubServer.IdpAndFederationShortCacheDurationAvailable = true;

            SpinWaiter.While(() =>
            {
                var mvu = subject.MetadataValidUntil;
                return !mvu.HasValue || mvu == DateTime.MinValue;
            },
            "Timed out waiting for successful reload of metadata.");
        }

        [TestMethod]
        public void IdentityProvider_ScheduledReloadOfMetadata_RetriesIfInitialLoadFails()
        {
            MetadataRefreshScheduler.minInterval = new TimeSpan(0, 0, 0, 0, 1);
            StubServer.IdpAndFederationShortCacheDurationAvailable = false;

            var subject = CreateSubjectForMetadataRefresh();

            StubServer.IdpAndFederationShortCacheDurationAvailable = true;

            SpinWaiter.While(() =>
            {
                var mvu = subject.MetadataValidUntil;
                return !mvu.HasValue || mvu == DateTime.MinValue;
            });
        }

        [TestMethod]
        public void IdentityProvider_ConstructedFromEntityDescriptor_DoesntReloadMetadataWhenDisabled()
        {
            var ed = new ExtendedEntityDescriptor
            {
                ValidUntil = DateTime.UtcNow.AddYears(-1),
                EntityId = new EntityId("someEntityId")
            };

            var idpSsoDescriptor = new IdentityProviderSingleSignOnDescriptor();
            idpSsoDescriptor.ProtocolsSupported.Add(new Uri("urn:oasis:names:tc:SAML:2.0:protocol"));
            ed.RoleDescriptors.Add(idpSsoDescriptor);

            idpSsoDescriptor.SingleSignOnServices.Add(new ProtocolEndpoint()
            {
                Binding = Saml2Binding.HttpRedirectUri,
                Location = new Uri("http://idp.example.com/sso")
            });

            idpSsoDescriptor.Keys.Add(SignedXmlHelper.TestKeyDescriptor);

            var subject = new IdentityProvider(ed.EntityId, StubFactory.CreateSPOptions());

            Action a = () => { var b = subject.Binding; };

            subject.LoadMetadata.Should().BeFalse();

            // Will throw invalid Uri if it tries to use EntityId as metadata url.
            a.ShouldNotThrow();
        }

        [TestMethod]
        public void IdentityProvider_ConstructedFromEntityDescriptor_DoesntScheduleMedataRefresh()
        {
            MetadataRefreshScheduler.minInterval = new TimeSpan(0, 0, 0, 0, 1);

            var ed = new ExtendedEntityDescriptor
            {
                ValidUntil = DateTime.UtcNow.AddYears(-1),
                EntityId = new EntityId("http://localhost:13428/idpMetadata")
            };

            var idpSsoDescriptor = new IdentityProviderSingleSignOnDescriptor();
            idpSsoDescriptor.ProtocolsSupported.Add(new Uri("urn:oasis:names:tc:SAML:2.0:protocol"));
            ed.RoleDescriptors.Add(idpSsoDescriptor);

            var pe = new ProtocolEndpoint()
            {
                Binding = Saml2Binding.HttpRedirectUri,
                Location = new Uri("http://idp.example.com/sso")
            };

            idpSsoDescriptor.SingleSignOnServices.Add(pe);

            idpSsoDescriptor.Keys.Add(SignedXmlHelper.TestKeyDescriptor);

            var subject = new IdentityProvider(ed.EntityId, StubFactory.CreateSPOptions());
            subject.ReadMetadata(ed);

            // Ugly, but have to wait and see that nothing happened. Have tried
            // some different timeouts but need 100 to ensure fail before bug
            // is fixed :-(
            Thread.Sleep(100);

            // Would be changed if metadata was reloaded.
            subject.SingleSignOnServiceUrl.Should().Be(pe.Location);
        }

        [TestMethod]
        public void IdentityProvider_MetadataLoadedConfiguredFromCode()
        {
            var subject = new IdentityProvider(
                new EntityId("http://other.entityid.example.com"),
                StubFactory.CreateSPOptions())
            {
                MetadataUrl = new Uri("http://localhost:13428/idpMetadataOtherEntityId"),
                AllowUnsolicitedAuthnResponse = true
            };

            subject.AllowUnsolicitedAuthnResponse.Should().BeTrue();
            subject.Binding.Should().Be(Saml2BindingType.HttpRedirect);
            subject.EntityId.Id.Should().Be("http://other.entityid.example.com");
            // If a metadatalocation is set, metadata loading is automatically enabled.
            subject.LoadMetadata.Should().BeTrue();
            subject.MetadataUrl.OriginalString.Should().Be("http://localhost:13428/idpMetadataOtherEntityId");
            subject.MetadataValidUntil.Should().BeCloseTo(
                DateTime.UtcNow.Add(MetadataRefreshScheduler.DefaultMetadataCacheDuration));
            subject.SingleSignOnServiceUrl.Should().Be("http://wrong.entityid.example.com/acs");

            Action a = () => subject.CreateAuthenticateRequest(null, StubFactory.CreateAuthServicesUrls());
            a.ShouldNotThrow();
        }

        [TestMethod]
        public void IdentityProvider_NoMetadataLoadConfiguredFromCode()
        {
            var subject = new IdentityProvider(
                new EntityId("http://idp.example.com"),
                StubFactory.CreateSPOptions())
                {
                    AllowUnsolicitedAuthnResponse = true,
                    Binding = Saml2BindingType.HttpPost,
                    SingleSignOnServiceUrl = new Uri("http://idp.example.com/sso")
                };

            subject.SigningKeys.AddConfiguredItem(SignedXmlHelper.TestKey);

            subject.AllowUnsolicitedAuthnResponse.Should().BeTrue();
            subject.Binding.Should().Be(Saml2BindingType.HttpPost);
            subject.EntityId.Id.Should().Be("http://idp.example.com");
            subject.LoadMetadata.Should().BeFalse();
            subject.MetadataUrl.OriginalString.Should().Be("http://idp.example.com");
            subject.MetadataValidUntil.Should().NotHaveValue();

            var subjectKeyParams = subject.SigningKeys.Single().As<RSACryptoServiceProvider>().ExportParameters(false);
            var expectedKeyParams = SignedXmlHelper.TestKey.As<RSACryptoServiceProvider>().ExportParameters(false);

            subjectKeyParams.Modulus.ShouldBeEquivalentTo(expectedKeyParams.Modulus);
            subjectKeyParams.Exponent.ShouldBeEquivalentTo(expectedKeyParams.Exponent);

            subject.SingleSignOnServiceUrl.AbsoluteUri.Should().Be("http://idp.example.com/sso");
        }

        [TestMethod]
        public void IdentityProvider_ReadMetadata_Nullcheck()
        {
            var subject = new IdentityProvider(
                new EntityId("http://idp.example.com"),
                StubFactory.CreateSPOptions());

            Action a = () => subject.ReadMetadata(null);

            a.ShouldThrow<ArgumentNullException>().And.ParamName.Should().Be("metadata");
        }
    }
}
