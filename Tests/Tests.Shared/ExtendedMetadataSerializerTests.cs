using System;
using System.Globalization;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using System.Text;
using FluentAssertions;
using Sustainsys.Saml2.Metadata;
using System.Xml.Linq;
using Sustainsys.Saml2.WebSso;
using System.Linq;
using Sustainsys.Saml2.Tokens;

namespace Sustainsys.Saml2.Tests
{
    [TestClass]
    public class ExtendedMetadataSerializerTests
    {
        [TestMethod]
        public void ExtendedMetadataSerializer_Read_EntityDescriptorValidUntil()
        {
            var data =
@"<EntityDescriptor xmlns=""urn:oasis:names:tc:SAML:2.0:metadata""
  entityID=""http://idp.example.com/"" validUntil=""2100-01-02T14:42:43Z"" />";

            var entityDescriptor = ExtendedMetadataSerializer.ReaderInstance.ReadMetadata(
                new MemoryStream(Encoding.UTF8.GetBytes(data)));

            var subject = entityDescriptor as EntityDescriptor;

            subject.Should().NotBeNull();
            subject.ValidUntil.Should().Be(new DateTime(2100, 01, 02, 14, 42, 43, DateTimeKind.Utc));
			subject.CacheDuration.Should().BeNull();
        }

        [TestMethod]
        public void ExtendedMetadataSerializer_Read_EntityDescriptorCacheDuration()
        {
            var data =
@"<EntityDescriptor xmlns=""urn:oasis:names:tc:SAML:2.0:metadata""
  entityID=""http://idp.example.com/"" cacheDuration=""PT42M"" />";

            var entityDescriptor = ExtendedMetadataSerializer.ReaderInstance.ReadMetadata(
                new MemoryStream(Encoding.UTF8.GetBytes(data)));

            var subject = entityDescriptor as EntityDescriptor;

            subject.Should().NotBeNull();
            subject.ValidUntil.Should().NotHaveValue();
            subject.CacheDuration.Should().Be(new XsdDuration(minutes: 42));
        }

        [TestMethod]
        public void ExtendedMetadataSerializer_Read_EntitiesDescriptorValidUntil()
        {
            var data =
@"<EntitiesDescriptor xmlns=""urn:oasis:names:tc:SAML:2.0:metadata""
  validUntil=""2100-01-02T14:42:43Z"">
  <EntityDescriptor entityID=""http://idp.example.com"" />
</EntitiesDescriptor>
";

            var entitiesDescriptor = ExtendedMetadataSerializer.ReaderInstance.ReadMetadata(
                new MemoryStream(Encoding.UTF8.GetBytes(data)));

            var subject = entitiesDescriptor as EntitiesDescriptor;

            subject.Should().NotBeNull();
            subject.ValidUntil.Should().Be(new DateTime(2100, 01, 02, 14, 42, 43, DateTimeKind.Utc));
			subject.CacheDuration.Should().BeNull();
        }

        [TestMethod]
        public void ExtendedMetadataSerializer_Read_EntitiesDescriptorCacheDuration()
        {
            var data =
@"<EntitiesDescriptor xmlns=""urn:oasis:names:tc:SAML:2.0:metadata""
  cacheDuration=""PT15M"">
  <EntityDescriptor entityID=""http://idp.example.com"" />
</EntitiesDescriptor>"
;

            var entitiesDescriptor = ExtendedMetadataSerializer.ReaderInstance.ReadMetadata(
                new MemoryStream(Encoding.UTF8.GetBytes(data)));

            var subject = entitiesDescriptor as EntitiesDescriptor;

            subject.Should().NotBeNull();
            subject.ValidUntil.Should().NotHaveValue();
            subject.CacheDuration.Should().Be(new XsdDuration(minutes: 15));
        }

        [TestMethod]
        public void ExtendedMetadataSerializer_Write_EntitiesDescriptorCacheDuration()
        {
			var metadata = new EntitiesDescriptor
			{
				Name = "Federation Name",
				CacheDuration = new XsdDuration(minutes: 42)
            };

			var entity = new EntityDescriptor
			{
				EntityId = new EntityId("http://some.entity.example.com")
			};

            var idpSsoDescriptor = new IdpSsoDescriptor();
            idpSsoDescriptor.ProtocolsSupported.Add(new Uri("urn:oasis:names:tc:SAML:2.0:protocol"));

            idpSsoDescriptor.SingleSignOnServices.Add(new SingleSignOnService
                {
                    Binding = Saml2Binding.HttpRedirectUri,
                    Location = new Uri("http://some.entity.example.com/sso")
                });
            entity.RoleDescriptors.Add(idpSsoDescriptor);

            metadata.ChildEntities.Add(entity);

            var stream = new MemoryStream();
            ExtendedMetadataSerializer.ReaderInstance.WriteMetadata(stream, metadata);
            stream.Seek(0, SeekOrigin.Begin);

            var result = XDocument.Load(stream).Root;

            result.Name.Should().Be(Saml2Namespaces.Saml2Metadata + "EntitiesDescriptor");
            result.Attribute("cacheDuration").Value.Should().Be("PT42M");

            result.Element(Saml2Namespaces.Saml2Metadata + "EntityDescriptor").Attribute("cacheDuration")
                .Should().BeNull();
        }

        [TestMethod]
        public void ExtendedMetadataSerializer_Read_X509DataWithMultipleInfo()
        {
            var data =
@"<EntityDescriptor entityID=""login004.test.stockholm.se""
  xmlns=""urn:oasis:names:tc:SAML:2.0:metadata"">
  <IDPSSODescriptor WantAuthnRequestsSigned=""false"" protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol"">
    <KeyDescriptor use=""signing"">
      <ns1:KeyInfo xmlns:ns1=""http://www.w3.org/2000/09/xmldsig#"" Id=""SM1fa34b49eb23d806ea829a9f5f949c1ceff1b9142d8"">
        <ns1:X509Data>
          <ns1:X509IssuerSerial>
            <ns1:X509IssuerName>E=arende@servicecentrum.stockholm.se,CN=Stockholm CA idPortal Internal Use,OU=idPortal Tieto,O=Stockholms Stad,ST=Stockholm,C=SE</ns1:X509IssuerName>
            <ns1:X509SerialNumber>12364142347751398823</ns1:X509SerialNumber>
          </ns1:X509IssuerSerial>
          <ns1:X509Certificate>MIIDbTCCAtagAwIBAgIJAKuWQfUOFh2nMA0GCSqGSIb3DQEBBQUAMIG0MQswCQYDVQQGEwJTRTESMBAGA1UECBMJU3RvY2tob2xtMRgwFgYDVQQKEw9TdG9ja2hvbG1zIFN0YWQxFzAVBgNVBAsTDmlkUG9ydGFsIFRpZXRvMSswKQYDVQQDEyJTdG9ja2hvbG0gQ0EgaWRQb3J0YWwgSW50ZXJuYWwgVXNlMTEwLwYJKoZIhvcNAQkBFiJhcmVuZGVAc2VydmljZWNlbnRydW0uc3RvY2tob2xtLnNlMB4XDTE0MTAwOTEzMDUyMloXDTE3MTAwOTEzMDUyMlowgb4xCzAJBgNVBAYTAlNFMRIwEAYDVQQIEwlTdG9ja2hvbG0xEjAQBgNVBAcTCVN0b2NraG9sbTEaMBgGA1UEChMRQ2l0eSBPZiBTdG9ja2hvbG0xEzARBgNVBAsTCmlkUG9ydGFsZW4xIzAhBgNVBAMTGmxvZ2luMDA0LnRlc3Quc3RvY2tob2xtLnNlMTEwLwYJKoZIhvcNAQkBFiJhcmVuZGVAc2VydmljZWNlbnRydW0uc3RvY2tob2xtLnNlMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCyizB5uoNMlNZhlnCMeXBD/60pltM/tVg4/y0Mk+zFztHId8BoUtuGk5Z3gQRXb/SuFkE41bhLB2SiArvEgjFjaGEH+FtBOuDiansY9cersWnntvkKGhUt6bxSeG+AKrh7rA8yf4CwQvIQw9jQqGyGeVuaxe7ilGcVHwmDotQWhwIDAQABo3sweTAJBgNVHRMEAjAAMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQUlCG8ZSkU6QTHp+tVBedxmn3VglIwHwYDVR0jBBgwFoAUxl8NEFIKt39mKUdrXjIr4syL9lkwDQYJKoZIhvcNAQEFBQADgYEAuCDEJuFuibTI7SomuAM3cH33rjVsBriXtZPp1Fvu9TidHzOueFv9MR+K3DRH+x0PDvGJwA5vlegTwD7qGWcYp80gItkqMhO2nYuIn/9DyPKebtSIM4dSosvmlSTD1bKdEfDM87WpitrTz+Ma6jc59Djiq//h678toVdV6Sm0TkY=</ns1:X509Certificate>
          <ns1:X509SubjectName>E=arende@servicecentrum.stockholm.se,CN=login004.test.stockholm.se,OU=idPortalen,O=City Of Stockholm,L=Stockholm,ST=Stockholm,C=SE</ns1:X509SubjectName>
        </ns1:X509Data>
      </ns1:KeyInfo>
    </KeyDescriptor>
  </IDPSSODescriptor>
</EntityDescriptor>";
            var entityDescriptor = (EntityDescriptor)ExtendedMetadataSerializer.ReaderInstance.ReadMetadata(
                new MemoryStream(Encoding.UTF8.GetBytes(data)));

            var keyInfo = entityDescriptor.RoleDescriptors.Cast<IdpSsoDescriptor>()
               .Single().Keys.Single().KeyInfo;

            keyInfo.Data.Count.Should().Be(1);
			keyInfo.Data.First().Should().BeOfType<X509Data>();
			var x509Data = keyInfo.Data.First().As<X509Data>();
			
			x509Data.IssuerSerial.Should().NotBeNull();
			x509Data.IssuerSerial.Name.Should().Be("E=arende@servicecentrum.stockholm.se,CN=Stockholm CA idPortal Internal Use,OU=idPortal Tieto,O=Stockholms Stad,ST=Stockholm,C=SE");
			x509Data.IssuerSerial.Serial.Should().Be("12364142347751398823");

			x509Data.Certificates.Count.Should().Be(1);
			
			x509Data.SubjectName.Should().NotBeNull();
			x509Data.SubjectName.Should().Be("E=arende@servicecentrum.stockholm.se,CN=login004.test.stockholm.se,OU=idPortalen,O=City Of Stockholm,L=Stockholm,ST=Stockholm,C=SE");
		}

		[TestMethod]
        public void ExtendedMetadataSerializer_Read_KeyName()
        {
            var data =
@"<md:EntityDescriptor xmlns:md=""urn:oasis:names:tc:SAML:2.0:metadata"" entityID=""http://idp-acc.test.ek.sll.se/neas"">
  <md:IDPSSODescriptor WantAuthnRequestsSigned=""true"" protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol"">
    <md:KeyDescriptor use=""signing"">
      <ds:KeyInfo xmlns:ds=""http://www.w3.org/2000/09/xmldsig#"">
        <ds:X509Data>
          <ds:X509Certificate>
MIIDYDCCAkgCCQDdrvhAIZlF8zANBgkqhkiG9w0BAQUFADByMQswCQYDVQQGEwJTRTEXMBUGA1UE
CAwOU3RvY2tob2xtcyBsYW4xEjAQBgNVBAcMCVN0b2NraG9sbTEVMBMGA1UECgwMMTYyMzIxMDAw
MDE2MR8wHQYDVQQDDBZpZHAtYWNjLnRlc3QuZWsuc2xsLnNlMB4XDTE0MDIxMzExMTkyOVoXDTI0
MDIxMTExMTkyOVowcjELMAkGA1UEBhMCU0UxFzAVBgNVBAgMDlN0b2NraG9sbXMgbGFuMRIwEAYD
VQQHDAlTdG9ja2hvbG0xFTATBgNVBAoMDDE2MjMyMTAwMDAxNjEfMB0GA1UEAwwWaWRwLWFjYy50
ZXN0LmVrLnNsbC5zZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANGsLRYFrhS/iQaG
w410eQ3wrEW/tA8t/PTUjSoy/jWYEL8GvfMNPggC2SSb45tAhvnItnyD0wFRGUjUJ84xrCtl9fSX
Z7GAGfE4RaHHXoVXjztMQXMrfusSSdsu2I0QDNKeoiTRNCTAWcR45pwvqNUqIagbT15xz7vqC3tP
Guo9lMMp4TL32gnQmtCcskE7qdYn+LJmLlb04ZzsJvNZ1bVpbTzGKmclcpHekrt/N44EjEkFnlP5
Ki3KgIXPEGbUALIsImfN/y+XqXQV/KqbGRD8likTLf5mhBykzOvX5PT5E7AcZntzJa59xaMs8dWE
i1cHSy7Q+T6z48a/XxcQEnMCAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAFO8old2aELkxryMoWpeU
EWECwUwQgUSGPpx4eCrGcoSw9Vf4R5EV3WQxE0VZ/IfwLEVwFoewhTCaGEwmBPjbuk7In8n+RsA1
WFKEi1XIX2IMiRPTszMLZY39zGVkr1aijoE7UmxMRlmH45FJlhJ0R8N2nRsLM2BylF7toTlozAGC
jfMzDBJshtuRdTAGWzWpJd+sijbGitCl8D9c5pB/G/iqdA770eNqcYUogjUyF2rEnaafx34h3T1r
gosrSG6sO3IPeL4BncKqqZO2FokfZbaqPBv6xmoKsVTUTQRfNEks84dRiG0MjqBncR+B6CIrCv2a
3hq3zHRCfk7EbFjuBw==
          </ds:X509Certificate>
        </ds:X509Data>
        <ds:KeyName>6b66c9b9e6612b7d5d9f4078daeca7a8e0d9815e</ds:KeyName>
      </ds:KeyInfo>
    </md:KeyDescriptor>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>";

            var entityDescriptor = (EntityDescriptor)ExtendedMetadataSerializer.ReaderInstance.ReadMetadata(
                new MemoryStream(Encoding.UTF8.GetBytes(data)));

            var keyInfo = entityDescriptor.RoleDescriptors.Cast<IdpSsoDescriptor>()
               .Single().Keys.Single().KeyInfo;

			keyInfo.Data.Count.Should().Be(1);
			keyInfo.Data.First().Should().BeOfType<X509Data>();
			var x509Data = keyInfo.Data.First().As<X509Data>();
			x509Data.Certificates.Count.Should().Be(1);
			Convert.ToBase64String(x509Data.Certificates.First().GetRawCertData()).Should().StartWith(
				"MIIDYDCCAkgCCQDdrvhAIZlF8zANBgkqhkiG9w0BAQUFADByMQswCQYDVQQGEwJTRTEXMBUGA1UE");

			keyInfo.KeyNames.Count.Should().Be(1);
			keyInfo.KeyNames.First().Should().Be("6b66c9b9e6612b7d5d9f4078daeca7a8e0d9815e");
		}

		[TestMethod]
        public void ExtendedMetadataSerializer_Read_ExtraElementInKeyInfoIgnored()
        {
            var data =
@"<md:EntityDescriptor xmlns:md=""urn:oasis:names:tc:SAML:2.0:metadata"" entityID=""http://idp-acc.test.ek.sll.se/neas"">
  <md:IDPSSODescriptor WantAuthnRequestsSigned=""true"" protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol"">
    <md:KeyDescriptor use=""signing"">
      <ds:KeyInfo xmlns:ds=""http://www.w3.org/2000/09/xmldsig#"">
        <MyCustomElement xmlns=""urn:MyNamespace"" />
      </ds:KeyInfo>
    </md:KeyDescriptor>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>";

            var entityDescriptor = (EntityDescriptor)ExtendedMetadataSerializer.ReaderInstance.ReadMetadata(
                new MemoryStream(Encoding.UTF8.GetBytes(data)));

			var keyInfo = entityDescriptor.RoleDescriptors.Cast<IdpSsoDescriptor>()
			   .Single().Keys.Single().KeyInfo;

			keyInfo.KeyNames.Count.Should().Be(0);
			keyInfo.KeyValues.Count.Should().Be(0);
			keyInfo.RetrievalMethods.Count.Should().Be(0);
			keyInfo.Data.Count.Should().Be(0);
		}

        [TestMethod]
        public void ExtendedMetadataSerializer_Read_RsaKey()
        {
            var data =
@"<md:EntityDescriptor xmlns:md=""urn:oasis:names:tc:SAML:2.0:metadata"" entityID=""http://idp-acc.test.ek.sll.se/neas"">
  <md:IDPSSODescriptor WantAuthnRequestsSigned=""true"" protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol"">
    <md:KeyDescriptor>
      <ds:KeyInfo xmlns:ds=""http://www.w3.org/2000/09/xmldsig#"">
        <ds:KeyValue>
          <ds:RSAKeyValue>
            <ds:Modulus>AKoYq6Q7UN7vOFmPr4fSq2NORXHBMKm8p7h4JnQU+quLRxvYll9cn8OBhIXq9SnCYkbzBVBkqN4ZyMM4vlSWy66wWdwLNYFDtEo1RJ6yZBExIaRVvX/eP6yRnpS1b7m7T2Uc2yPq1DnWzVI+sIGR51s1/ROnQZswkPJHh71PThln</ds:Modulus>
            <ds:Exponent>AQAB</ds:Exponent>
          </ds:RSAKeyValue>
        </ds:KeyValue>
      </ds:KeyInfo>
    </md:KeyDescriptor>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>";

            var entityDescriptor = (EntityDescriptor)ExtendedMetadataSerializer.ReaderInstance.ReadMetadata(
                new MemoryStream(Encoding.UTF8.GetBytes(data)));

			var keyInfo = entityDescriptor.RoleDescriptors.Cast<IdpSsoDescriptor>()
			   .Single().Keys.Single().KeyInfo;

            keyInfo.KeyValues.Count.Should().Be(1);
            keyInfo.KeyValues.First().Should().BeOfType<RsaKeyValue>();
        }

        [TestMethod]
        public void ExtendedMetadataSerializer_Read_ServiceProviderSingleSignOnDescriptor()
        {
			// This test is dealing with the issue of SPs having duplicate index numbers on their AssertionConsumerServices
            var data =
@"<md:EntityDescriptor xmlns:md=""urn:oasis:names:tc:SAML:2.0:metadata"" entityID=""http://idp-acc.test.ek.sll.se/neas"">
    <md:SPSSODescriptor AuthnRequestsSigned=""false"" WantAssertionsSigned=""true"" protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol"">
      <md:SingleLogoutService Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"" Location=""https://maggie.bif.ost.se:9443/sp/saml/slo/HTTP-POST""/>
      <md:AssertionConsumerService Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"" Location=""https://maggie.bif.ost.se:9443/sp/saml/sso/HTTP-POST"" index=""1"" isDefault=""true""/>
      <md:AssertionConsumerService Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"" Location=""https://maggie.bif.ost.se:9443/sp/saml/sso/POST"" index=""1"" isDefault=""true""/>
	</md:SPSSODescriptor>
 </md:EntityDescriptor>";

            var entityDescriptor = (EntityDescriptor)ExtendedMetadataSerializer.ReaderInstance.ReadMetadata(
                new MemoryStream(Encoding.UTF8.GetBytes(data)));

            var spssoInfo = entityDescriptor.RoleDescriptors.Cast<SpSsoDescriptor>().Single();

            spssoInfo.AssertionConsumerServices.Count.Should().Be(0);
        }

        [TestMethod]
        public void ExtendedMetadataSerializer_Read_Organization()
        {
            var data =
@"<md:EntityDescriptor xmlns:md=""urn:oasis:names:tc:SAML:2.0:metadata"" entityID=""http://idp-acc.test.ek.sll.se/neas"">
    <md:Organization>
      <md:OrganizationName xml:lang=""en"">Test Org</md:OrganizationName>
      <md:OrganizationDisplayName xml:lang=""en"">Test Org Name</md:OrganizationDisplayName>
      <md:OrganizationURL xml:lang=""en"">https://idp.maggie.bif.ost.se:9445/idp/saml</md:OrganizationURL>
      <md:OrganizationURL xml:lang=""da"">https://idp.maggie.bif.ost.se:9445/idp/saml</md:OrganizationURL>
    </md:Organization>
  </md:EntityDescriptor>";

            var entityDescriptor = (EntityDescriptor)ExtendedMetadataSerializer.ReaderInstance.ReadMetadata(
                new MemoryStream(Encoding.UTF8.GetBytes(data)));

            var organizationInfo = entityDescriptor.Organization;

			// TODO: I don't follow this either -- the test was asserting there were 0, 0 and 0 results
			organizationInfo.Names.Count.Should().Be(1);
            organizationInfo.DisplayNames.Count.Should().Be(1);
            organizationInfo.Urls.Count.Should().Be(2);
        }
    }
}
