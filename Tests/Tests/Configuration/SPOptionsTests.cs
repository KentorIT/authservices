using System;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Sustainsys.Saml2.Configuration;
using System.IdentityModel.Metadata;
using FluentAssertions;
using Sustainsys.Saml2.Saml2P;
using System.Security.Cryptography.Xml;
using Sustainsys.Saml2.TestHelpers;

namespace Sustainsys.Saml2.Tests.Configuration
{
    [TestClass]
    public class SPOptionsTests
    {
        [TestCleanup]
        public void TestCleanup()
        {
            if(!SustainsysSaml2Section.Current.IsReadOnly())
            {
                SustainsysSaml2Section.Current.AuthenticateRequestSigningBehavior = SigningBehavior.Never;
                SustainsysSaml2Section.Current.ValidateCertificates = false;
                SustainsysSaml2Section.Current.AllowChange = false;
                SustainsysSaml2Section.Current.Metadata.WantAssertionsSigned = false;
                SustainsysSaml2Section.Current.Metadata.AllowChange = false;
                SustainsysSaml2Section.Current.Compatibility.UnpackEntitiesDescriptorInIdentityProviderMetadata = false;
                SustainsysSaml2Section.Current.Compatibility.DisableLogoutStateCookie = false;
                SustainsysSaml2Section.Current.Compatibility.IgnoreMissingInResponseTo = false;
                SustainsysSaml2Section.Current.Compatibility.AcceptOneTimeUseAssertions = false;
                SustainsysSaml2Section.Current.Compatibility.AllowChange = false;
            }
        }

        const string entityId = "http://localhost/idp";
        const string otherEntityId = "http://something.else.com";

        [TestMethod]
        public void SPOptions_Saml2PSecurityTokenHandler_DefaultInstanceCreated()
        {
            var subject = new SPOptions
            {
                EntityId = new EntityId(entityId)
            };

            subject.Saml2PSecurityTokenHandler.Should().NotBeNull();
            subject.Saml2PSecurityTokenHandler.Configuration.AudienceRestriction.AllowedAudienceUris
                .Should().Contain(new Uri(entityId));
        }

        [TestMethod]
        public void SPOptions_Constructor_ThrowsOnNullConfiguration()
        {
            Action a = () => new SPOptions(null);

            a.ShouldThrow<ArgumentNullException>().And.ParamName.Should().Be("configSection");
        }

        [TestMethod]
        public void SPOptions_Constructor_LoadsConfig()
        {
            var config = SustainsysSaml2Section.Current;
            config.AllowChange = true;
            config.AuthenticateRequestSigningBehavior = SigningBehavior.Always;
            config.Metadata.AllowChange = true;
            config.Metadata.WantAssertionsSigned = true;
            config.ValidateCertificates = true;
            config.Compatibility.AllowChange = true;
            config.Compatibility.UnpackEntitiesDescriptorInIdentityProviderMetadata = true;
            config.Compatibility.DisableLogoutStateCookie = true;
            config.Compatibility.IgnoreMissingInResponseTo = true;
            config.Compatibility.AcceptOneTimeUseAssertions = true;

            SPOptions subject = new SPOptions(SustainsysSaml2Section.Current);
            subject.ReturnUrl.Should().Be(config.ReturnUrl);
            subject.MetadataCacheDuration.Should().Be(config.Metadata.CacheDuration);
            subject.MetadataValidDuration.Should().Be(config.Metadata.ValidUntil);
            subject.WantAssertionsSigned.Should().Be(true);
            subject.ValidateCertificates.Should().Be(true);
            subject.DiscoveryServiceUrl.Should().Be(config.DiscoveryServiceUrl);
            subject.EntityId.Should().Be(config.EntityId);
            subject.ModulePath.Should().Be(config.ModulePath);
            subject.NameIdPolicy.AllowCreate.Should().Be(config.NameIdPolicyElement.AllowCreate);
            subject.NameIdPolicy.Format.Should().Be(config.NameIdPolicyElement.Format);
            subject.Organization.Should().Be(config.organization);
            subject.AuthenticateRequestSigningBehavior.Should().Be(config.AuthenticateRequestSigningBehavior);
            subject.OutboundSigningAlgorithm.Should().Be(SignedXml.XmlDsigRSASHA256Url);
            subject.MinIncomingSigningAlgorithm.Should().Be(SignedXml.XmlDsigRSASHA1Url);
            subject.RequestedAuthnContext.ClassRef.OriginalString.Should().Be("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
            subject.RequestedAuthnContext.Comparison.Should().Be(AuthnContextComparisonType.Minimum);
            subject.Compatibility.UnpackEntitiesDescriptorInIdentityProviderMetadata.Should().BeTrue();
            subject.Compatibility.DisableLogoutStateCookie.Should().BeTrue();
            subject.Compatibility.IgnoreMissingInResponseTo.Should().BeTrue();
            subject.Compatibility.AcceptOneTimeUseAssertions.Should().BeTrue();
        }

        [TestMethod]
        public void SPOptions_EntityId_SettingThrowsIfTokenHandlerCreated()
        {
            var subject = new SPOptions
            {
                EntityId = new EntityId(entityId)
            };

            subject.Saml2PSecurityTokenHandler.Should().NotBeNull();

            Action a = () => subject.EntityId = new EntityId(otherEntityId);

            a.ShouldThrow<InvalidOperationException>("Can't change entity id when a token handler has been instantiated.");
        }

        [TestMethod]
        public void SPOPtions_ModulePath_Default()
        {
            var subject = new SPOptions();
            subject.ModulePath.Should().Be("/Saml2");
        }

        [TestMethod]
        public void SPOPtions_ModulePath_NonDefault()
        {
            var subject = new SPOptions();
            subject.ModulePath = "/Foo";
            subject.ModulePath.Should().Be("/Foo");
        }

        [TestMethod]
        public void SPOptions_ModulePath_FixesSlashes()
        {
            var subject = new SPOptions();
            subject.ModulePath = "Foo/";
            subject.ModulePath.Should().Be("/Foo");
        }

        [TestMethod]
        public void SPOptions_ModulePath_RejectsNull()
        {
            var subject = new SPOptions();
            Action a = () => subject.ModulePath = null;

            a.ShouldThrow<ArgumentNullException>().And.ParamName.Should().Be("value");
        }

        [TestMethod]
        public void SPOptions_Contacts_IsntNull()
        {
            var subject = new SPOptions();

            subject.Contacts.Should().NotBeNull();
        }

        [TestMethod]
        public void SPOptions_MetadataDuration_DefaultValues()
        {
            var subject = new SPOptions();

            subject.MetadataCacheDuration.Should().Be(new TimeSpan(1, 0, 0));
            subject.MetadataValidDuration.Should().NotHaveValue();
        }

        [TestMethod]
        public void SPOptions_SigningAlgorithm_DefaultValue()
        {
            var subject = new SPOptions();

            subject.OutboundSigningAlgorithm.Should().Be(SignedXml.XmlDsigRSASHA256Url);
        }

        [TestMethod]
        public void SPOptions_MinIncomingSigningAlgorithm_DefaultValue()
        {
            var subject = new SPOptions();

            subject.MinIncomingSigningAlgorithm.Should().Be(SignedXml.XmlDsigRSASHA256Url);
        }

        [TestMethod]
        public void SPOptions_MininumSigningAlgorithm_ThrowsOnUnknownAlgorithm()
        {
            var subject = new SPOptions();

            subject.Invoking(s => s.MinIncomingSigningAlgorithm = "InvalidName")
                .ShouldThrow<ArgumentException>()
                .WithMessage("*unknown*not supported*");
        }

        [TestMethod]
        public void SPOptions_SigningCertificate_NullWhenEmpty()
        {
            var subject = new SPOptions();

            subject.SigningServiceCertificate.Should().Be(null);
        }

        [TestMethod]
        public void SPOptions_SigningCertificate_SingleSigning()
        {
            var subject = new SPOptions();
            subject.ServiceCertificates.Add(new ServiceCertificate
            {
                Use = CertificateUse.Signing,
                Certificate = SignedXmlHelper.TestCert
            });

            subject.SigningServiceCertificate.SerialNumber.Should().Be(SignedXmlHelper.TestCert.SerialNumber);
        }

        [TestMethod]
        public void SPOptions_SigningCertificate_SingleUnspecified()
        {
            var subject = new SPOptions();
            subject.ServiceCertificates.Add(new ServiceCertificate {
                Use = CertificateUse.Signing,
                Certificate = SignedXmlHelper.TestCert });

            subject.SigningServiceCertificate.SerialNumber.Should().Be(SignedXmlHelper.TestCert.SerialNumber);
        }

        [TestMethod]
        public void SPOptions_SigningCertificate_UseCurrentWhenFuturePublished()
        {
            var subject = new SPOptions();
            subject.ServiceCertificates.Add(new ServiceCertificate { Certificate = SignedXmlHelper.TestCert2 });
            subject.ServiceCertificates.Add(new ServiceCertificate { Status = CertificateStatus.Future, Certificate = SignedXmlHelper.TestCert });

            subject.SigningServiceCertificate.SerialNumber.Should().Be(SignedXmlHelper.TestCert2.SerialNumber);
        }

        [TestMethod]
        public void SPOptions_SigningCertificate_NullWhenOnlyDecryptionCerts()
        {
            var subject = new SPOptions();
            subject.ServiceCertificates.Add(new ServiceCertificate { Use = CertificateUse.Encryption, Certificate = SignedXmlHelper.TestCert2 });

            subject.SigningServiceCertificate.Should().Be(null);
        }

        [TestMethod]
        public void SPOptions_DecryptionCertificate_EmptyWhenNoneAdded()
        {
            var subject = new SPOptions();

            subject.DecryptionServiceCertificates.Count.Should().Be(0);
        }

        [TestMethod]
        public void SPOptions_DecryptionCertificate_SingleUnspecified()
        {
            var subject = new SPOptions();
            subject.ServiceCertificates.Add(new ServiceCertificate { Certificate = SignedXmlHelper.TestCert });

            subject.DecryptionServiceCertificates.Count.Should().Be(1);
            subject.DecryptionServiceCertificates[0].SerialNumber.Should().Be(SignedXmlHelper.TestCert.SerialNumber);
        }

        [TestMethod]
        public void SPOptions_DecryptionCertificate_SingleEncryption()
        {
            var subject = new SPOptions();
            subject.ServiceCertificates.Add(new ServiceCertificate
            {
                Use = CertificateUse.Encryption,
                Certificate = SignedXmlHelper.TestCert
            });

            subject.DecryptionServiceCertificates.Count.Should().Be(1);
            subject.DecryptionServiceCertificates[0].SerialNumber.Should().Be(SignedXmlHelper.TestCert.SerialNumber);
        }

        [TestMethod]
        public void SPOptions_DecryptionCertificate_UseBothWhenFutureUnspecifiedPublished()
        {
            var subject = new SPOptions();
            subject.ServiceCertificates.Add(new ServiceCertificate { Certificate = SignedXmlHelper.TestCert2 });
            subject.ServiceCertificates.Add(new ServiceCertificate { Status = CertificateStatus.Future, Certificate = SignedXmlHelper.TestCert });

            subject.DecryptionServiceCertificates.Count.Should().Be(2);
            subject.DecryptionServiceCertificates[0].SerialNumber.Should().NotBe(subject.DecryptionServiceCertificates[1].SerialNumber);
        }

        [TestMethod]
        public void SPOptions_DecryptionCertificate_UseBothWhenFutureEncryptionPublished()
        {
            var subject = new SPOptions();
            subject.ServiceCertificates.Add(new ServiceCertificate { Certificate = SignedXmlHelper.TestCert2 });
            subject.ServiceCertificates.Add(new ServiceCertificate { Use = CertificateUse.Encryption, Status = CertificateStatus.Future, Certificate = SignedXmlHelper.TestCert });

            subject.DecryptionServiceCertificates.Count.Should().Be(2);
            subject.DecryptionServiceCertificates[0].SerialNumber.Should().NotBe(subject.DecryptionServiceCertificates[1].SerialNumber);
        }

        [TestMethod]
        public void SPOptions_DecryptionCertificate_EmptyWhenOnlySigning()
        {
            var subject = new SPOptions();
            subject.ServiceCertificates.Add(new ServiceCertificate { Use = CertificateUse.Signing, Certificate = SignedXmlHelper.TestCert2 });

            subject.DecryptionServiceCertificates.Count.Should().Be(0);
        }

        [TestMethod]
        public void SPOptions_MetadataCertificates_EmptyWhenNoneAdded()
        {
            var subject = new SPOptions();

            subject.MetadataCertificates.Count.Should().Be(0);
        }

        [TestMethod]
        public void SPOptions_MetadataCertificates_Single()
        {
            var subject = new SPOptions();
            subject.ServiceCertificates.Add(new ServiceCertificate { Certificate = SignedXmlHelper.TestCert });

            var result = subject.MetadataCertificates;
            result.Count.Should().Be(1);
            result[0].Certificate.SerialNumber.Should().Be(SignedXmlHelper.TestCert.SerialNumber);
        }

        [TestMethod]
        public void SPOptions_MetadataCertificates_CurrentBothBecomesSigning_WhenFutureBothPublished()
        {
            var subject = new SPOptions();
            subject.ServiceCertificates.Add(new ServiceCertificate { Certificate = SignedXmlHelper.TestCert });
            subject.ServiceCertificates.Add(new ServiceCertificate { Status = CertificateStatus.Future, Certificate = SignedXmlHelper.TestCert2 });

            var result = subject.MetadataCertificates;
            result.Count.Should().Be(2);
            // tests that we switch the current use to Signing so that Idp's stop sending us certs encrypted with the old key
            result.Where(c => c.Certificate.SerialNumber == SignedXmlHelper.TestCert.SerialNumber).First().Use.Should().Be(CertificateUse.Signing);
            result.Where(c => c.Certificate.SerialNumber == SignedXmlHelper.TestCert2.SerialNumber).First().Use.Should().Be(CertificateUse.Both);

            // prevent bug where the MetadataCertificates property modified the Use property of the same underlying object
            subject.ServiceCertificates.First().Use.Should().Be(CertificateUse.Both);
            subject.ServiceCertificates.Skip(1).Single().Use.Should().Be(CertificateUse.Both);
        }

        [TestMethod]
        public void SPOptions_MetadataCertificates_OnlyOneEncryptionPublished_FutureEncryption()
        {
            var subject = new SPOptions();
            subject.ServiceCertificates.Add(new ServiceCertificate
            {
                Use = CertificateUse.Encryption,
                Certificate = SignedXmlHelper.TestCert
            });
            subject.ServiceCertificates.Add(new ServiceCertificate
            {
                Use = CertificateUse.Encryption,
                Status = CertificateStatus.Future,
                Certificate = SignedXmlHelper.TestCert2
            });

            var result = subject.MetadataCertificates;
            result.Count.Should().Be(1);
            result[0].Status.Should().Be(CertificateStatus.Future);
        }

        [TestMethod]
        public void SPOptions_MetadataCertificates_OnlyOneEncryptionPublished_FutureBoth()
        {
            var subject = new SPOptions();
            subject.ServiceCertificates.Add(new ServiceCertificate
            {
                Use = CertificateUse.Encryption,
                Certificate = SignedXmlHelper.TestCert
            });
            subject.ServiceCertificates.Add(new ServiceCertificate
            {
                Use = CertificateUse.Both,
                Status = CertificateStatus.Future,
                Certificate = SignedXmlHelper.TestCert2
            });

            var result = subject.MetadataCertificates;
            result.Count.Should().Be(1);
            result[0].Status.Should().Be(CertificateStatus.Future);
        }

        [TestMethod]
        public void SPOptions_MetadataCertificates_BothSigningAndEncryptionPublished()
        {
            var subject = new SPOptions();
            subject.ServiceCertificates.Add(new ServiceCertificate
            {
                Use = CertificateUse.Encryption,
                Certificate = SignedXmlHelper.TestCert
            });
            subject.ServiceCertificates.Add(new ServiceCertificate
            {
                Use = CertificateUse.Signing,
                Certificate = SignedXmlHelper.TestCert2
            });

            var result = subject.MetadataCertificates;
            result.Count.Should().Be(2);
            result[0].Use.Should().NotBe(result[1].Use);
        }

        [TestMethod]
        public void SPOptions_MetadataCertificates_RolloverOnlyOneType()
        {
            var subject = new SPOptions();
            subject.ServiceCertificates.Add(new ServiceCertificate
            {
                Use = CertificateUse.Encryption,
                Certificate = SignedXmlHelper.TestCert
            });
            subject.ServiceCertificates.Add(new ServiceCertificate
            {
                Use = CertificateUse.Signing,
                Certificate = SignedXmlHelper.TestCertSignOnly
            });
            subject.ServiceCertificates.Add(new ServiceCertificate
            {
                Status = CertificateStatus.Future,
                Use = CertificateUse.Signing,
                Certificate = SignedXmlHelper.TestCert2
            });

            var result = subject.MetadataCertificates;
            result.Count.Should().Be(3);
            result.Where(c => c.Use == CertificateUse.Signing).Count().Should().Be(2);
            result.Where(c => c.Use == CertificateUse.Encryption).Count().Should().Be(1);
        }

        [TestMethod]
        public void SPOptions_MetadataCertificates_BothSigningPublished()
        {
            var subject = new SPOptions();
            subject.ServiceCertificates.Add(new ServiceCertificate
            {
                Use = CertificateUse.Signing,
                Certificate = SignedXmlHelper.TestCert
            });
            subject.ServiceCertificates.Add(new ServiceCertificate
            {
                Use = CertificateUse.Signing,
                Status = CertificateStatus.Future,
                Certificate = SignedXmlHelper.TestCert2
            });

            var result = subject.MetadataCertificates;
            result.Count.Should().Be(2);
            result[0].Certificate.SerialNumber.Should().NotBe(result[1].Certificate.SerialNumber);
        }

        [TestMethod]
        public void SPOptions_MetadataCertificates_OverrideDoNotPublish()
        {
            var subject = new SPOptions();
            subject.ServiceCertificates.Add(new ServiceCertificate
            {
                MetadataPublishOverride = MetadataPublishOverrideType.DoNotPublish,
                Certificate = SignedXmlHelper.TestCert
            });

            var result = subject.MetadataCertificates;
            result.Count.Should().Be(0);
        }

        [TestMethod]
        public void SPOptions_MetadataCertificates_OverridePublishSigning()
        {
            var subject = new SPOptions();
            subject.ServiceCertificates.Add(new ServiceCertificate
            {
                MetadataPublishOverride = MetadataPublishOverrideType.PublishSigning,
                Certificate = SignedXmlHelper.TestCert
            });

            var result = subject.MetadataCertificates;
            result.Count.Should().Be(1);
            result[0].Use.Should().Be(CertificateUse.Signing);
            // prevent bug where the MetadataCertificates property modified the Use property of the same underlying object
            subject.ServiceCertificates.Single().Use.Should().Be(CertificateUse.Both);
        }

        [TestMethod]
        public void SPOptions_MetadataCertificates_OverridePublishEncryption()
        {
            var subject = new SPOptions();
            subject.ServiceCertificates.Add(new ServiceCertificate
            {
                MetadataPublishOverride = MetadataPublishOverrideType.PublishEncryption,
                Certificate = SignedXmlHelper.TestCert
            });

            var result = subject.MetadataCertificates;
            result.Count.Should().Be(1);
            result[0].Use.Should().Be(CertificateUse.Encryption);
            // prevent bug where the MetadataCertificates property modified the Use property of the same underlying object
            subject.ServiceCertificates.Single().Use.Should().Be(CertificateUse.Both);
        }

        [TestMethod]
        public void SPOptions_MetadataCertificates_OverridePublishUnspecified()
        {
            var subject = new SPOptions();
            subject.ServiceCertificates.Add(new ServiceCertificate
            {
                Use = CertificateUse.Encryption,
                MetadataPublishOverride = MetadataPublishOverrideType.PublishUnspecified,
                Certificate = SignedXmlHelper.TestCert
            });

            var result = subject.MetadataCertificates;
            result.Count.Should().Be(1);
            result[0].Use.Should().Be(CertificateUse.Both);
            // prevent bug where the MetadataCertificates property modified the Use property of the same underlying object
            subject.ServiceCertificates.Single().Use.Should().Be(CertificateUse.Encryption);
        }

        [TestMethod]
        public void SPOptions_MetadataCertificates_BothEncryptionPublishedWithOverride()
        {
            var subject = new SPOptions();
            subject.ServiceCertificates.Add(new ServiceCertificate
            {
                Use = CertificateUse.Encryption,
                Certificate = SignedXmlHelper.TestCert,
                MetadataPublishOverride = MetadataPublishOverrideType.PublishEncryption
            });
            subject.ServiceCertificates.Add(new ServiceCertificate
            {
                Use = CertificateUse.Encryption,
                Status = CertificateStatus.Future,
                Certificate = SignedXmlHelper.TestCert2
            });

            var result = subject.MetadataCertificates;
            result.Count.Should().Be(2);
        }

        [TestMethod]
        public void SPOptions_MetadataCertificates_CurrentEncryptionRemainsPublished_IfFutureOverriddentoNotPublished()
        {
            var subject = new SPOptions();
            subject.ServiceCertificates.Add(new ServiceCertificate
            {
                Use = CertificateUse.Encryption,
                Certificate = SignedXmlHelper.TestCert
            });
            subject.ServiceCertificates.Add(new ServiceCertificate
            {
                Use = CertificateUse.Encryption,
                Status = CertificateStatus.Future,
                MetadataPublishOverride = MetadataPublishOverrideType.DoNotPublish,
                Certificate = SignedXmlHelper.TestCert2
            });

            var result = subject.MetadataCertificates;
            result.Count.Should().Be(1);
            result[0].Status.Should().Be(CertificateStatus.Current);
        }

        [TestMethod]
        public void SPOptions_Saml2PSecurityTokenHandler_Setter()
        {
            var subject = StubFactory.CreateSPOptions();

            var handler = new Saml2PSecurityTokenHandler(subject);

            subject.Saml2PSecurityTokenHandler = handler;

            subject.Saml2PSecurityTokenHandler.Should().BeSameAs(handler);
        }
    }
}
