using System.Linq;
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
using System.IdentityModel.Tokens;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography.X509Certificates;
using System.Security.Claims;
using System.Security.Principal;

namespace Kentor.AuthServices.Tests
{
    [TestClass]
    public class IdentityProviderTests
    {
        TimeSpan refreshMinInterval = MetadataRefreshScheduler.minInterval;
        int idpMetadataSsoPort = StubServer.IdpMetadataSsoPort;

        private IPrincipal currentPrincipal;

        [TestInitialize]
        public void Initialize()
        {
            currentPrincipal = Thread.CurrentPrincipal;
        }

        [TestCleanup]
        public void Cleanup()
        {
            StubServer.IdpMetadataSsoPort = idpMetadataSsoPort;
            StubServer.IdpVeryShortCacheDurationIncludeInvalidKey = false;
            StubServer.IdpVeryShortCacheDurationIncludeKey = true;
            MetadataRefreshScheduler.minInterval = refreshMinInterval;
            Thread.CurrentPrincipal = currentPrincipal;
        }

        [TestMethod]
        public void IdentityProvider_CreateAuthenticateRequest_DestinationInXml()
        {
            string idpUri = "https://idp.example.com:443/";

            var subject = new IdentityProvider(
                new EntityId(idpUri),
                Options.FromConfiguration.SPOptions)
                {
                    SingleSignOnServiceUrl = new Uri(idpUri)
                };

            var r = subject.CreateAuthenticateRequest(StubFactory.CreateAuthServicesUrls());

            r.ToXElement().Attribute("Destination").Should().NotBeNull()
                .And.Subject.Value.Should().Be(idpUri);
        }

        [TestMethod]
        public void IdentityProvider_CreateAuthenticateRequest_BasicInfo()
        {
            var options = Options.FromConfiguration;

            var idp = options.IdentityProviders.Default;

            var urls = StubFactory.CreateAuthServicesUrls();
            var subject = idp.CreateAuthenticateRequest(urls);

            var expected = new Saml2AuthenticationRequest()
            {
                AssertionConsumerServiceUrl = urls.AssertionConsumerServiceUrl,
                DestinationUrl = idp.SingleSignOnServiceUrl,
                Issuer = options.SPOptions.EntityId,
                AttributeConsumingServiceIndex = 0,
                NameIdPolicy = new Saml2NameIdPolicy(true, NameIdFormat.EntityIdentifier),
                RequestedAuthnContext = new Saml2RequestedAuthnContext(
                    new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"),
                    AuthnContextComparisonType.Minimum)
            };

            subject.ShouldBeEquivalentTo(expected, opt => opt
            .Excluding(au => au.Id)
            .Excluding(au=>au.SigningAlgorithm)
            .Excluding(au => au.RelayState));

            subject.RelayState.Should().HaveLength(24);
        }

        [TestMethod]
        public void IdentityProvider_CreateAuthenticateRequest_PublicOrigin()
        {
            var origin = new Uri("https://my.public.origin:8443/");
            var options = StubFactory.CreateOptionsPublicOrigin(origin);

            var idp = options.IdentityProviders.Default;

            var urls = StubFactory.CreateAuthServicesUrlsPublicOrigin(origin);
            var subject = idp.CreateAuthenticateRequest(urls);

            var expected = new Saml2AuthenticationRequest()
            {
                AssertionConsumerServiceUrl = urls.AssertionConsumerServiceUrl,
                DestinationUrl = idp.SingleSignOnServiceUrl,
                Issuer = options.SPOptions.EntityId,
                AttributeConsumingServiceIndex = 0
            };

            subject.ShouldBeEquivalentTo(expected, opt => opt
            .Excluding(au => au.Id)
            .Excluding(au => au.SigningAlgorithm)
            .Excluding(au => au.RelayState));
        }

        [TestMethod]
        public void IdentityProvider_CreateAuthenticateRequest_NoAttributeIndex()
        {
            var options = StubFactory.CreateOptions();
            var idp = options.IdentityProviders.Default;
            var urls = StubFactory.CreateAuthServicesUrls();

            options.SPOptions.AttributeConsumingServices.Clear();

            var subject = idp.CreateAuthenticateRequest(urls);

            var expected = new Saml2AuthenticationRequest()
            {
                AssertionConsumerServiceUrl = urls.AssertionConsumerServiceUrl,
                DestinationUrl = idp.SingleSignOnServiceUrl,
                Issuer = options.SPOptions.EntityId,
                AttributeConsumingServiceIndex = null
            };

            subject.ShouldBeEquivalentTo(expected, opt => opt
                .Excluding(au => au.Id)
                .Excluding(au => au.SigningAlgorithm)
                .Excluding(au => au.RelayState));
        }

        [TestMethod]
        public void IdentityProvider_CreateAuthenticateRequest_NullcheckAuthServicesUrls()
        {
            var idp = Options.FromConfiguration.IdentityProviders.Default;

            Action a = () => idp.CreateAuthenticateRequest(null);

            a.ShouldThrow<ArgumentNullException>().And.ParamName.Should().Be("authServicesUrls");
        }

        [TestMethod]
        public void IdentityProvider_CreateAuthenticateRequest_IncludesSigningCertificate_ForConfigAlways()
        {
            var options = StubFactory.CreateOptions();
            var spOptions = options.SPOptions;
            spOptions.AuthenticateRequestSigningBehavior = SigningBehavior.Always;
            spOptions.ServiceCertificates.Add(new ServiceCertificate
            {
                Certificate = SignedXmlHelper.TestCert
            });

            var idp = options.IdentityProviders.Default;
            var urls = StubFactory.CreateAuthServicesUrls();

            var subject = idp.CreateAuthenticateRequest(urls);

            subject.SigningCertificate.Thumbprint.Should().Be(SignedXmlHelper.TestCert.Thumbprint);
        }

        [TestMethod]
        public void IdentityProvider_CreateAuthenticateRequest_IncludesSigningCertificate_IfIdpWants()
        {
            var options = Options.FromConfiguration;
            var spOptions = options.SPOptions;

            var subject = options.IdentityProviders[new EntityId("https://idp2.example.com")];
            var urls = StubFactory.CreateAuthServicesUrls();

            var actual = subject.CreateAuthenticateRequest(urls).SigningCertificate;

            (actual?.Thumbprint).Should().Be(SignedXmlHelper.TestCert2.Thumbprint);
        }

        [TestMethod]
        public void IdentityProvider_CreateAuthenticateRequest_SigningBehaviorNever_OverridesIdpWantsRequestsSigned()
        {
            var options = StubFactory.CreateOptions();
            var spOptions = options.SPOptions;
            spOptions.AuthenticateRequestSigningBehavior = SigningBehavior.Never;
            spOptions.ServiceCertificates.Add(new ServiceCertificate
            {
                Certificate = SignedXmlHelper.TestCert
            });

            var subject = new IdentityProvider(new EntityId("http://idp.example.com"), spOptions)
            {
                WantAuthnRequestsSigned = true
            };
            var urls = StubFactory.CreateAuthServicesUrls();

            var actual = subject.CreateAuthenticateRequest(urls).SigningCertificate;

            actual.Should().BeNull();
        }

        [TestMethod]
        public void IdentityProvider_CreateAuthenticateRequest_ThrowsOnMissingSigningCertificate()
        {
            var options = StubFactory.CreateOptions();
            var spOptions = options.SPOptions;
            spOptions.AuthenticateRequestSigningBehavior = SigningBehavior.Always;

            var idp = options.IdentityProviders.Default;
            var urls = StubFactory.CreateAuthServicesUrls();

            idp.Invoking(i => i.CreateAuthenticateRequest(urls))
                .ShouldThrow<ConfigurationErrorsException>()
                .WithMessage($"Idp \"https://idp.example.com\" is configured for signed AuthenticateRequests*");
        }

        [TestMethod]
        public void IdentityProvider_Certificate_FromFile()
        {
            var subject = Options.FromConfiguration.IdentityProviders.Default;

            var key = ((X509RawDataKeyIdentifierClause)subject.SigningKeys.Single())
                .Matches(SignedXmlHelper.TestCert).Should().BeTrue();
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
            subject.SigningKeys.Single().ShouldBeEquivalentTo(new X509RawDataKeyIdentifierClause(SignedXmlHelper.TestCert));
            subject.ArtifactResolutionServiceUrls.Count.Should().Be(2);
            subject.ArtifactResolutionServiceUrls[0x1234].OriginalString
                .Should().Be("http://localhost:13428/ars");
            subject.ArtifactResolutionServiceUrls[117].OriginalString
                .Should().Be("http://localhost:13428/ars2");
            subject.SingleLogoutServiceUrl.OriginalString.Should().Be("http://localhost:13428/logout");
            subject.SingleLogoutServiceResponseUrl.OriginalString.Should().Be("http://localhost:13428/logoutResponse");
            subject.SingleLogoutServiceBinding.Should().Be(Saml2BindingType.HttpRedirect);
        }

        [TestMethod]
        public void IdentityProvider_ConfigFromMetadata_LogoutResponse_DefaultsToSingleLogoutServiceUrl()
        {
            var entityId = new EntityId("http://localhost:13428/idpMetadataNoCertificate");
            var subject = new IdentityProvider(entityId, StubFactory.CreateSPOptions());
            subject.SigningKeys.AddConfiguredKey(SignedXmlHelper.TestCert);

            subject.LoadMetadata = true;

            subject.SingleLogoutServiceResponseUrl.OriginalString.Should().Be("http://localhost:13428/logout");
            subject.SingleLogoutServiceBinding.Should().Be(Saml2BindingType.HttpRedirect);
        }

        private IdentityProviderElement CreateConfig()
        {
            var config = new IdentityProviderElement();
            config.AllowConfigEdit(true);
            config.Binding = Saml2BindingType.HttpPost;
            config.SigningCertificate = new CertificateElement();
            config.SigningCertificate.AllowConfigEdit(true);
            config.SigningCertificate.FileName = "Kentor.AuthServices.Tests.pfx";
            config.SignOnUrl = new Uri("http://idp.example.com/acs");
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
        public void IdentityProvider_Ctor_NullcheckSpOptions()
        {
            Action a = () => new IdentityProvider(new EntityId("urn:foo"), null);

            a.ShouldThrow<ArgumentNullException>()
                .And.ParamName.Should().Be("spOptions");
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
            config.SignOnUrl = null;
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
            subject.SigningKeys.Single().ShouldBeEquivalentTo(
                new X509RawDataKeyIdentifierClause(SignedXmlHelper.TestCert));
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
        public void IdentityProvider_Ctor_PrefersRedirectBindingForLogout()
        {
            var config = CreateConfig();
            config.LoadMetadata = true;
            config.EntityId = "http://localhost:13428/idpMetadataWithMultipleBindings";

            var subject = new IdentityProvider(config, Options.FromConfiguration.SPOptions);

            subject.SingleLogoutServiceBinding.Should().Be(Saml2BindingType.HttpRedirect);
            subject.SingleLogoutServiceUrl.Should().Be( "http://idp2Bindings.example.com/LogoutRedirect" );
        }

        [TestMethod]
        public void IdentityProvider_Ctor_UseMetadataLocationUrl()
        {
            var config = CreateConfig();
            config.MetadataLocation = "http://localhost:13428/idpMetadataDifferentEntityId";
            config.EntityId = "some-idp";

            var subject = new IdentityProvider(config, Options.FromConfiguration.SPOptions);

            subject.Binding.Should().Be(Saml2BindingType.HttpRedirect);
            subject.SingleSignOnServiceUrl.Should().Be("http://idp.example.com/SsoService");
        }

        [TestMethod]
        public void IdentityProvider_Ctor_LogoutBindingDefaultsToBinding()
        {
            var config = CreateConfig();
            var subject = new IdentityProvider(config, StubFactory.CreateSPOptions());

            subject.Binding.Should().Be(Saml2BindingType.HttpPost);
            subject.SingleLogoutServiceBinding.Should().Be(Saml2BindingType.HttpPost);
        }

        [TestMethod]
        public void IdentityProvider_Ctor_DisableOutboundLogoutRequest()
        {
            var config = CreateConfig();
            config.DisableOutboundLogoutRequests = true;

            var subject = new IdentityProvider(config, StubFactory.CreateSPOptions());

            subject.DisableOutboundLogoutRequests.Should().BeTrue();
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

            var expectedValidUntil = DateTime.UtcNow.AddHours(1);
            // Comparison on the second is more than enough if we're adding 1 hour.
            subject.MetadataValidUntil.Should().BeCloseTo(expectedValidUntil, 1000);
        }

        IdentityProvider CreateSubjectForMetadataRefresh(bool setLoggerToNull = false)
        {
            var config = CreateConfig();
            config.LoadMetadata = true;
            config.EntityId = "http://localhost:13428/idpMetadataVeryShortCacheDuration";
            var spOptions = Options.FromConfiguration.SPOptions;
            if(setLoggerToNull)
            {
                spOptions = StubFactory.CreateSPOptions();
                spOptions.Logger = null;
            }
            return new IdentityProvider(config, spOptions);
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
        public void IdentityProvider_SingleLogoutServiceBinding_ReloadsMetadataIfNoLongerValid()
        {
            StubServer.IdpVeryShortCacheDurationBinding = Saml2Binding.HttpRedirectUri;
            var subject = CreateSubjectForMetadataRefresh();
            subject.SingleLogoutServiceBinding.Should().Be(Saml2BindingType.HttpRedirect);
            StubServer.IdpVeryShortCacheDurationBinding = Saml2Binding.HttpPostUri;

            SpinWaiter.WhileEqual(() => subject.SingleLogoutServiceBinding, () => Saml2BindingType.HttpRedirect);

            subject.SingleLogoutServiceBinding.Should().Be(Saml2BindingType.HttpPost);
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
        public void IdentityProvider_SingleLogoutServiceUrl_ReloadsMetadataIfNoLongerValid()
        {
            StubServer.IdpAndFederationVeryShortCacheDurationPort = 42;
            var subject = CreateSubjectForMetadataRefresh();
            subject.SingleLogoutServiceUrl.Port.Should().Be(42);
            StubServer.IdpAndFederationVeryShortCacheDurationPort = 117;

            SpinWaiter.WhileEqual(() => subject.SingleLogoutServiceUrl.Port, () => 42);

            subject.SingleLogoutServiceUrl.Port.Should().Be(117);
        }

        [TestMethod]
        public void IdentityProvider_SingleLogoutServiceResponseUrl_ReloadsMetadataIfNoLongerValid()
        {
            StubServer.IdpAndFederationVeryShortCacheDurationPort = 42;
            var subject = CreateSubjectForMetadataRefresh();
            subject.SingleLogoutServiceResponseUrl.Port.Should().Be(42);
            StubServer.IdpAndFederationVeryShortCacheDurationPort = 117;

            SpinWaiter.WhileEqual(() => subject.SingleLogoutServiceResponseUrl.Port, () => 42);

            subject.SingleLogoutServiceResponseUrl.Port.Should().Be(117);
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

            new X509Certificate2(
                subject.SigningKeys.Single().As<X509RawDataKeyIdentifierClause>()
                .GetX509RawData()).Thumbprint.Should().Be(SignedXmlHelper.TestCert.Thumbprint);
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

            var subject = CreateSubjectForMetadataRefresh(true);

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
            var spOptions = StubFactory.CreateSPOptions();

            spOptions.ServiceCertificates.Add(new ServiceCertificate()
            {
                Certificate = SignedXmlHelper.TestCert
            });

            var subject = new IdentityProvider(
                new EntityId("http://other.entityid.example.com"), spOptions)
            {
                MetadataLocation = "http://localhost:13428/idpMetadataOtherEntityId",
                AllowUnsolicitedAuthnResponse = true
            };

            subject.AllowUnsolicitedAuthnResponse.Should().BeTrue();
            subject.Binding.Should().Be(Saml2BindingType.HttpRedirect);
            subject.EntityId.Id.Should().Be("http://other.entityid.example.com");
            // If a metadatalocation is set, metadata loading is automatically enabled.
            subject.LoadMetadata.Should().BeTrue();
            subject.MetadataLocation.Should().Be("http://localhost:13428/idpMetadataOtherEntityId");
            subject.MetadataValidUntil.Should().BeCloseTo(DateTime.UtcNow.AddDays(1), precision: 100);
            subject.SingleSignOnServiceUrl.Should().Be("http://wrong.entityid.example.com/acs");
            subject.WantAuthnRequestsSigned.Should().Be(true, "WantAuthnRequestsSigned should have been loaded from metadata");

            Action a = () => subject.CreateAuthenticateRequest(StubFactory.CreateAuthServicesUrls());
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

            subject.SigningKeys.AddConfiguredKey(SignedXmlHelper.TestKey);

            subject.AllowUnsolicitedAuthnResponse.Should().BeTrue();
            subject.Binding.Should().Be(Saml2BindingType.HttpPost);
            subject.EntityId.Id.Should().Be("http://idp.example.com");
            subject.LoadMetadata.Should().BeFalse();
            subject.MetadataLocation.Should().Be("http://idp.example.com");
            subject.MetadataValidUntil.Should().NotHaveValue();

            var subjectKeyParams = subject.SigningKeys.Single().CreateKey()
                .As<RsaSecurityKey>().GetAsymmetricAlgorithm(SecurityAlgorithms.RsaSha1Signature, false).As<RSA>()
                .ExportParameters(false);

            var expectedKeyParams = SignedXmlHelper.TestCert.PublicKey.Key.As<RSA>()
                .ExportParameters(false);
                
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

        [TestMethod]
        public void IdentityProvider_MetadataLocation_UnpacksEntitiesDescriptor_if_configured()
        {
            var spOptions = StubFactory.CreateSPOptions();
            spOptions.Compatibility.UnpackEntitiesDescriptorInIdentityProviderMetadata = true;

            var subject = new IdentityProvider(
                new EntityId("http://idp.federation.example.com/metadata"),
                spOptions);

            Action a = () => subject.MetadataLocation = "~/Metadata/SingleIdpInEntitiesDescriptor.xml";

            a.ShouldNotThrow();
        }

        [TestMethod]
        public void IdentityProvider_MetadataLocation_ThrowsWhenEntitiesDescriptorFoundAndNotAllowedByConfig()
        {
            var spOptions = StubFactory.CreateSPOptions();
            spOptions.Compatibility.UnpackEntitiesDescriptorInIdentityProviderMetadata.Should().BeFalse();

            var subject = new IdentityProvider(
                new EntityId("http://idp.example.com"),
                spOptions);

            Action a = () => subject.MetadataLocation = "~/Metadata/SingleIdpInEntitiesDescriptor.xml";

            a.ShouldThrow<InvalidOperationException>();
        }

        [TestMethod]
        public void IdentityProvider_CreateLogoutRequest()
        {
            var options = StubFactory.CreateOptions();
            options.SPOptions.ServiceCertificates.Add(new ServiceCertificate()
            {
                Certificate = SignedXmlHelper.TestCert
            });

            var subject = options.IdentityProviders[0];

            var logoutNameIdClaim = new Claim(
                AuthServicesClaimTypes.LogoutNameIdentifier, ",,urn:nameIdFormat,,NameId", null, subject.EntityId.Id);

            var user = new ClaimsPrincipal(new ClaimsIdentity(
                new Claim[]
                {
                    logoutNameIdClaim,
                    new Claim(AuthServicesClaimTypes.SessionIndex, "SessionId", null, subject.EntityId.Id)
                }, "Federation"));

            // Grab a datetime both before and after creation to handle case
            // when the second part is changed during excecution of the test.
            // We're assuming that the creation does not take more than a
            // second, so two values will do.
            var beforeTime = DateTime.UtcNow.ToSaml2DateTimeString();
            var actual = subject.CreateLogoutRequest(user);
            var aftertime = DateTime.UtcNow.ToSaml2DateTimeString();

            actual.Issuer.Id.Should().Be(options.SPOptions.EntityId.Id);
            actual.Id.Value.Should().NotBeEmpty();
            actual.IssueInstant.Should().Match(i => i == beforeTime || i == aftertime);
            actual.SessionIndex.Should().Be("SessionId");
            actual.SigningCertificate.Thumbprint.Should().Be(SignedXmlHelper.TestCert.Thumbprint);

            var expectedNameId = new Saml2NameIdentifier("NameId")
            {
                Format = new Uri("urn:nameIdFormat")
            };
            actual.NameId.ShouldBeEquivalentTo(expectedNameId);
        }

        [TestMethod]
        public void IdentityProvider_CreateLogoutRequest_IgnoresThreadPrincipal()
        {
            var options = StubFactory.CreateOptions();
            options.SPOptions.ServiceCertificates.Add(new ServiceCertificate()
            {
                Certificate = SignedXmlHelper.TestCert
            });

            var subject = options.IdentityProviders[0];

            Thread.CurrentPrincipal = new ClaimsPrincipal(new ClaimsIdentity(
                new Claim[]
                {
                    new Claim(ClaimTypes.NameIdentifier, "ThreadNameId"),
                    new Claim(AuthServicesClaimTypes.LogoutNameIdentifier, "ThreadLogoutNameId", null, subject.EntityId.Id),
                    new Claim(AuthServicesClaimTypes.SessionIndex, "ThreadSessionId", null, subject.EntityId.Id)
                }, "Federation"));

            var user = new ClaimsPrincipal(new ClaimsIdentity(
                new Claim[]
                {
                    new Claim(AuthServicesClaimTypes.LogoutNameIdentifier, ",,,,Saml2NameId", null, subject.EntityId.Id),
                    new Claim(AuthServicesClaimTypes.SessionIndex, "SessionId", null, subject.EntityId.Id)
                }, "Federation"));

            var actual = subject.CreateLogoutRequest(user);

            actual.NameId.Value.Should().Be("Saml2NameId");
            actual.SessionIndex.Should().Be("SessionId");
        }

        [TestMethod]
        public void IdentityProvider_CreateLogoutRequest_FailsIfNoSigningCertificateConfigured()
        {
            var options = StubFactory.CreateOptions();
            var subject = options.IdentityProviders[0];

            var user = new ClaimsPrincipal(new ClaimsIdentity(
                new Claim[]
                {
                    new Claim(ClaimTypes.NameIdentifier, "NameId", null, subject.EntityId.Id),
                    new Claim(AuthServicesClaimTypes.SessionIndex, "SessionId", null, subject.EntityId.Id)
                }, "Federation"));

            subject.Invoking(s => s.CreateLogoutRequest(user))
                .ShouldThrow<InvalidOperationException>()
                .And.Message.Should().Be($"Tried to issue single logout request to https://idp.example.com, but no signing certificate for the SP is configured and single logout requires signing. Add a certificate to the ISPOptions.ServiceCertificates collection, or to <serviceCertificates> element if you're using web.config.");
        }

        [TestMethod]
        public void IdentityProvider_CreateLogoutRequest_UserNullCheck()
        {
            var options = StubFactory.CreateOptions();
            var subject = options.IdentityProviders[0];

            ClaimsPrincipal user = null;

            subject.Invoking(s => s.CreateLogoutRequest(user))
                .ShouldThrow<ArgumentNullException>()
                .And.Message.Should().Be("Value cannot be null.\r\nParameter name: user");
        }

        [TestMethod]
        public void IdentityProvider_SingleLogoutServiceResponseUrl()
        {
            var subject = new IdentityProvider(new EntityId("http://example.com"), StubFactory.CreateSPOptions());
            var url = new Uri("http://some.url.example.com/logout-response");

            subject.SingleLogoutServiceResponseUrl = url;

            subject.SingleLogoutServiceResponseUrl.OriginalString.Should().Be(url.OriginalString);
        }
    }
}
