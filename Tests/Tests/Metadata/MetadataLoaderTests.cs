using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IdentityModel.Metadata;
using FluentAssertions;
using System.Xml.Linq;
using System.Linq;
using Sustainsys.Saml2.Metadata;
using System.Net;
using System.IO;

namespace Sustainsys.Saml2.Tests.Metadata
{
    [TestClass]
    public class MetadataLoaderTests
    {
        [TestMethod]
        public void MetadataLoader_LoadIdp_ByLocation()
        {
            var entityId = "http://localhost:13428/idpMetadata";
            var subject = MetadataLoader.LoadIdp(entityId);

            subject.EntityId.Id.Should().Be(entityId);
        }

        [TestMethod]
        public void MetadataLoader_LoadIdp_ByStream()
        {
            var entityId = "http://localhost:13428/idpMetadata";
            using (var client = new WebClient())
            using (var metadataStream = client.OpenRead(entityId))
            {
                var subject = MetadataLoader.LoadIdp(metadataStream);

                subject.EntityId.Id.Should().Be(entityId);
            }
        }

        [TestMethod]
        public void MetadataLoader_LoadIdp_NullStringCheck()
        {
            Action a = () => MetadataLoader.LoadIdp((string)null);

            a.ShouldThrow<ArgumentNullException>().And.ParamName.Should().Be("metadataLocation");
        }

        [TestMethod]
        public void MetadataLoader_LoadIdp_NullStreamCheck()
        {
            Action a = () => MetadataLoader.LoadIdp((Stream)null);

            a.ShouldThrow<ArgumentNullException>().And.ParamName.Should().Be("metadataStream");
        }

        [TestMethod]
        public void MetadataLoader_LoadIdp_ExplanatoryExceptionIfEntitiesDescriptorFound()
        {
            var metadataLocation = "http://localhost:13428/federationMetadata";

            Action a = () => MetadataLoader.LoadIdp(metadataLocation);

            a.ShouldThrow<InvalidOperationException>().
                WithMessage(MetadataLoader.LoadIdpFoundEntitiesDescriptor);
        }

        [TestMethod]
        public void MetadataLoader_LoadFederation_NullStringCheck()
        {
            Action a = () => MetadataLoader.LoadFederation((string)null);

            a.ShouldThrow<ArgumentNullException>().And.ParamName.Should().Be("metadataLocation");
        }

        [TestMethod]
        public void MetadataLoader_LoadFederation_NullStreamCheck()
        {
            Action a = () => MetadataLoader.LoadFederation((Stream)null);

            a.ShouldThrow<ArgumentNullException>().And.ParamName.Should().Be("metadataStream");
        }

        [TestMethod]
        public void MetadataLoader_LoadFederation()
        {
            var metadataLocation = "http://localhost:13428/federationMetadata";

            var subject = MetadataLoader.LoadFederation(metadataLocation);

            subject.ChildEntities.First().EntityId.Id.Should().Be("http://idp.federation.example.com/metadata");
        }

        [TestMethod]
        public void MetadataLoader_LoadFederation_FromFile()
        {
            var metadataLocation = "~/Metadata/SambiMetadata.xml";

            var result = MetadataLoader.LoadFederation(metadataLocation);

            result.ChildEntities.First().EntityId.Id.Should().Be("https://idp.maggie.bif.ost.se:9445/idp/saml");
        }

        [TestMethod]
        public void MetadataLoader_LoadFederation_FromStream()
        {
            var metadataLocation = "http://localhost:13428/federationMetadata";

            using (var client = new WebClient())
            using (var metadataStream = client.OpenRead(metadataLocation))
            {
                var subject = MetadataLoader.LoadFederation(metadataStream);

                subject.ChildEntities.First().EntityId.Id.Should().Be("http://idp.federation.example.com/metadata");
            }
        }

        [TestMethod]
        public void MetadataLoader_LoadFederation_ExplanatoryExceptionIfEntitiesDescriptorFound()
        {
            var entityId = "http://localhost:13428/idpMetadata";

            Action a = () => MetadataLoader.LoadFederation(entityId);

            a.ShouldThrow<InvalidOperationException>().
                WithMessage(MetadataLoader.LoadFederationFoundEntityDescriptor);
        }

        [TestMethod]
        public void MetadataLoader_LoadIdentityProvider_UnpacksEntitiesDescriptorIfFlagSet()
        {
            var metadataLocation = "~/Metadata/SingleIdpInEntitiesDescriptor.xml";

            var actual = MetadataLoader.LoadIdp(metadataLocation, true);

            actual.Should().BeOfType<ExtendedEntityDescriptor>();
        }

        [TestMethod]
        public void MetadataLoader_LoadIdentityProvider_ThrowsOnMultipleEntityDescriptorsWhenUnpackingEntitiesDescriptor()
        {
            var metadataLocation = "~/Metadata/SambiMetadata.xml";

            Action a = () => MetadataLoader.LoadIdp(metadataLocation, true);

            a.ShouldThrow<InvalidOperationException>()
                .WithMessage(MetadataLoader.LoadIdpUnpackingFoundMultipleEntityDescriptors);
        }
    }
}