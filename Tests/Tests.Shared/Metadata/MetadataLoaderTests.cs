using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using FluentAssertions;
using System.Xml.Linq;
using System.Linq;
using Sustainsys.Saml2.Metadata;
using System.Text;
using System.IO.Compression;
using System.IO;

namespace Sustainsys.Saml2.Tests.Metadata
{
    [TestClass]
    public class MetadataLoaderTests
    {
        [TestMethod]
        public void MetadataLoader_LoadIdp()
        {
            var entityId = "http://localhost:13428/idpMetadata";
            var subject = MetadataLoader.LoadIdp(entityId);

            subject.EntityId.Id.Should().Be(entityId);
        }

        [TestMethod]
        public void MetadataLoader_LoadIdp_Nullcheck()
        {
            Action a = () => MetadataLoader.LoadIdp(null);

            a.Should().Throw<ArgumentNullException>().And.ParamName.Should().Be("metadataLocation");
        }

        [TestMethod]
        public void MetadataLoader_LoadIdp_ExplanatoryExceptionIfEntitiesDescriptorFound()
        {
            var metadataLocation = "http://localhost:13428/federationMetadata";

            Action a = () => MetadataLoader.LoadIdp(metadataLocation);

            a.Should().Throw<InvalidOperationException>().
                WithMessage(MetadataLoader.LoadIdpFoundEntitiesDescriptor);
        }

        [TestMethod]
        public void MetadataLoader_LoadFromMemoryStream()
        {
            var metadataLocation = GetZippedMemoryStreamMetadataLocationFromString(GetSampleMetadataAsXmlString());

            var entityDescriptor =  (EntityDescriptor)MetadataLoader.LoadIdp(metadataLocation);
            string entityId = ((EntityDescriptor)entityDescriptor).EntityId.Id;

            entityDescriptor.RoleDescriptors.Count.Should().BeGreaterThan(0);            
            entityId.Should().Be("http://www.okta.com/5gk0r9r7h4hs0s0ffggd");
        }

        private string GetSampleMetadataAsXmlString()
        {
            return @"<?xml version=""1.0"" encoding=""UTF-8""?><md:EntityDescriptor entityID=""http://www.okta.com/5gk0r9r7h4hs0s0ffggd"" xmlns:md=""urn:oasis:names:tc:SAML:2.0:metadata""><md:IDPSSODescriptor WantAuthnRequestsSigned=""false"" protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol""><md:KeyDescriptor use=""signing""><ds:KeyInfo xmlns:ds=""http://www.w3.org/2000/09/xmldsig#""><ds:X509Data><ds:X509Certificate>MIIDpDCCAoygAwIBAgIGAVjUlPBHMA0GCSqGSIb3DQEBBQUAMIGSMQswCQYDVQQGEwJVUzETMBEG
                                    A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
                                    MBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi00ODkwODIxHDAaBgkqhkiG9w0BCQEW
                                    DWluZm9Ab2t0YS5jb20wHhcNMTYxMjA2MTQ0MDIwWhcNMjYxMjA2MTQ0MTIwWjCBkjELMAkGA1UE
                                    BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNV
                                    BAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtNDg5MDgyMRwwGgYJ
                                    KoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
                                    iO0EkZVg0IJ2Ab0mDenn1P1EbAtIxgWs/vtY5B71WfqgrGvleTkFDw7wXq9R7DBDTFGpEuYyoOG0
                                    Ez7sjaMbqVgKhiBlj1PDWWh2EDzrh4Gq8PVyH3vUd8ofp3KqWdMq1ZcFJk9ow42voY3cXmH4249z
                                    NnbIa5ZJpTwYgdwfN5RULf91NsDK1m1t7Z48LjX68pZh5bb4ES3UqWv1GS8vdYF02lqZPDq7DMmG
                                    YnNJKhVzz99Ux01StrHWCioRlHhEExsiW0M5HYYK+sO6dCZOesThkz52d67W53xh8+KvnfY4t/J4
                                    i/F7ch0TIzYnBfoaoJQw06lGGoLsuUikSYZd3wIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBZ1kA+
                                    zNnmmJ4VlBGEwm/wEnVjP8DhaVShVIsQmw9ZkhkqNkNhRLRReIreDT4bHIN+YgEMA+Kqq3Ma6p0I
                                    GIglm2mIOU1EqZ9ZGzBxR4s5KpKY9WLFYvy/FsPy4D1knQJeevlg1szR84Xirug4AqrBuIpTVtio
                                    wE9Z5GCA/ScXybLoFXB9advcj/UZ5TYHshk04Qmti2Hhl3Yt6vXUlA7HEJXr4Q+hQJk2uBPv6nVS
                                    SPAv6wpo458pILVLrZTecGQ/xylF9z4jFEyKVXGN3XdbeVgx5uQiOTdIrZPES5we6JfqqiDqqHoM
                                    FtaHSwS5GWCwb4j+QuUaki/NlA+tj1wL</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
                                    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:x509SubjectName</md:NameIDFormat><md:SingleSignOnService Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"" Location=""https://dev.oktapreview.com/app/""/>
                                    <md:SingleSignOnService Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"" Location=""https://dev.oktapreview.com/app/""/></md:IDPSSODescriptor></md:EntityDescriptor>";

        }

        private string GetZippedMemoryStreamMetadataLocationFromString(string xmlContent)
        {
            byte[] buffer = Encoding.UTF8.GetBytes(xmlContent);
            var memoryStream = new MemoryStream();
            using (var gZipStream = new GZipStream(memoryStream, CompressionMode.Compress, true))
            {
                gZipStream.Write(buffer, 0, buffer.Length);
            }

            memoryStream.Position = 0;

            var compressedData = new byte[memoryStream.Length];
            memoryStream.Read(compressedData, 0, compressedData.Length);

            var gZipBuffer = new byte[compressedData.Length + 4];
            Buffer.BlockCopy(compressedData, 0, gZipBuffer, 4, compressedData.Length);
            Buffer.BlockCopy(BitConverter.GetBytes(buffer.Length), 0, gZipBuffer, 0, 4);
            return Convert.ToBase64String(gZipBuffer);
        }

        [TestMethod]
        public void MetadataLoader_LoadFederation_Nullcheck()
        {
            Action a = () => MetadataLoader.LoadFederation(null);

            a.Should().Throw<ArgumentNullException>().And.ParamName.Should().Be("metadataLocation");
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
        public void MetadataLoader_LoadFederation_ExplanatoryExceptionIfEntitiesDescriptorFound()
        {
            var entityId = "http://localhost:13428/idpMetadata";

            Action a = () => MetadataLoader.LoadFederation(entityId);

            a.Should().Throw<InvalidOperationException>().
                WithMessage(MetadataLoader.LoadFederationFoundEntityDescriptor);
        }

        [TestMethod]
        public void MetadataLoader_LoadIdentityProvider_UnpacksEntitiesDescriptorIfFlagSet()
        {
            var metadataLocation = "~/Metadata/SingleIdpInEntitiesDescriptor.xml";

            var actual = MetadataLoader.LoadIdp(metadataLocation, true);

            actual.Should().BeOfType<EntityDescriptor>();
        }

        [TestMethod]
        public void MetadataLoader_LoadIdentityProvider_ThrowsOnMultipleEntityDescriptorsWhenUnpackingEntitiesDescriptor()
        {
            var metadataLocation = "~/Metadata/SambiMetadata.xml";

            Action a = () => MetadataLoader.LoadIdp(metadataLocation, true);

            a.Should().Throw<InvalidOperationException>()
                .WithMessage(MetadataLoader.LoadIdpUnpackingFoundMultipleEntityDescriptors);
        }
    }
}
