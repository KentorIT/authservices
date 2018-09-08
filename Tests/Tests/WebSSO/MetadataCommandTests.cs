using System;
using System.Xml.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using FluentAssertions;
using System.IdentityModel.Metadata;
using Sustainsys.Saml2.Configuration;
using Sustainsys.Saml2.WebSso;
using Sustainsys.Saml2.Tests.Helpers;
using System.Security.Cryptography.Xml;
using Sustainsys.Saml2.TestHelpers;
using Sustainsys.Saml2.Saml2P;

namespace Sustainsys.Saml2.Tests.WebSso
{
    [TestClass]
    public class MetadataCommandTests
    {
        [TestMethod]
        public void MetadataCommand_Run_NullcheckOptions()
        {
            Action a = () => new MetadataCommand().Run(
                new HttpRequestData("GET", new Uri("http://localhost")), 
                null);

            a.ShouldThrow<ArgumentNullException>().And.ParamName.Should().Be("options");
        }

        HttpRequestData request = new HttpRequestData("GET", new Uri("http://localhost"));

        [TestMethod]
        public void MetadataCommand_Run_CompleteMetadata()
        {
            var options = StubFactory.CreateOptions();
            options.SPOptions.DiscoveryServiceUrl = new Uri("http://ds.example.com");
            options.SPOptions.AuthenticateRequestSigningBehavior = SigningBehavior.Always;
            options.SPOptions.OutboundSigningAlgorithm = SignedXml.XmlDsigRSASHA384Url;
            options.SPOptions.NameIdPolicy = new Saml2NameIdPolicy(true, NameIdFormat.EmailAddress);
            options.SPOptions.ServiceCertificates.Add(new ServiceCertificate()
            {
                Certificate = SignedXmlHelper.TestCertSignOnly,
                Use = CertificateUse.Signing,
                MetadataPublishOverride = MetadataPublishOverrideType.PublishUnspecified
            });

            var subject = new MetadataCommand().Run(request, options);

            var payloadXml = XmlHelpers.XmlDocumentFromString(subject.Content);

            // Validate signature, location of it  and then drop it. It contains
            // a reference to the ID which makes it unsuitable for string matching.
            payloadXml.DocumentElement.IsSignedBy(SignedXmlHelper.TestCertSignOnly).Should().BeTrue();
            payloadXml.DocumentElement.FirstChild.LocalName.Should().Be("Signature");
            payloadXml.DocumentElement.FirstChild["KeyInfo"].Should().NotBeNull();
            payloadXml.DocumentElement.FirstChild["SignedInfo"]["SignatureMethod"].GetAttribute("Algorithm")
                .Should().Be(SignedXml.XmlDsigRSASHA384Url);
            payloadXml.DocumentElement.RemoveChild("Signature", SignedXml.XmlDsigNamespaceUrl);

            // Ignore the ID attribute, it is just filled with a GUID that can't be easily tested.
            payloadXml.DocumentElement.Attributes.Remove("ID");

            // Test and then drop validUntil, can't be text compared.
            DateTime.Parse(payloadXml.DocumentElement.Attributes["validUntil"].Value)
                .Should().BeCloseTo(DateTime.UtcNow.AddDays(24).ToLocalTime(), 2000);
            payloadXml.DocumentElement.Attributes.Remove("validUntil");

            var expectedXml =
            "<EntityDescriptor entityID=\"https://github.com/SustainsysIT/Saml2\" cacheDuration=\"PT42S\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\">"
            + "<SPSSODescriptor AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">"
            + "<Extensions>"
            + "<DiscoveryResponse Binding=\"urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol\" Location=\"http://localhost/Saml2/SignIn\" index=\"0\" isDefault=\"true\" xmlns=\"urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol\" />"
            + "</Extensions>"
            + "<KeyDescriptor><KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Data><X509Certificate>MIIDIzCCAg+gAwIBAgIQg7mOjTf994NAVxZu4jqXpzAJBgUrDgMCHQUAMCQxIjAgBgNVBAMTGUtlbnRvci5BdXRoU2VydmljZXMuVGVzdHMwHhcNMTMwOTI1MTMzNTQ0WhcNMzkxMjMxMjM1OTU5WjAkMSIwIAYDVQQDExlLZW50b3IuQXV0aFNlcnZpY2VzLlRlc3RzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwVGpfvK9N//MnA5Jo1q2liyPR24406Dp25gv7LB3HK4DWgqsb7xXM6KIV/WVOyCV2g/O1ErBlB+HLhVZ4XUJvbqBbgAJqFO+TZwcCIe8u4nTEXeU660FdtkKClA17sbtMrAGdDfOPwVBHSuavdHeD7jHNI4RUDGKnEW13/0EvnHDilIetwODRxrX/+41R24sJThFbMczByS3OAL2dcIxoAynaGeM90gXsVYow1QhJUy21+cictikb7jW4mW6dvFCBrWIceom9J295DcQIHoxJy5NoZwMir/JV00qs1wDVoN20Ve1DC5ImwcG46XPF7efQ44yLh2j5Yexw+xloA81dwIDAQABo1kwVzBVBgNVHQEETjBMgBAWIahoZhXVUogbAqkS7zwfoSYwJDEiMCAGA1UEAxMZS2VudG9yLkF1dGhTZXJ2aWNlcy5UZXN0c4IQg7mOjTf994NAVxZu4jqXpzAJBgUrDgMCHQUAA4IBAQA2aGzmuKw4AYXWMhrGj5+i8vyAoifUn1QVOFsUukEA77CrqhqqaWFoeagfJp/45vlvrfrEwtF0QcWfmO9w1VvHwm7sk1G/cdYyJ71sU+llDsdPZm7LxQvWZYkK+xELcinQpSwt4ExavS+jLcHoOYHYwIZMBn3U8wZw7Kq29oGnoFQz7HLCEl/G9i3QRyvFITNlWTjoScaqMjHTzq6HCMaRsL09DLcY3KB+cedfpC0/MBlzaxZv0DctTulyaDfM9DCYOyokGN/rQ6qkAR0DDm8fVwknbJY7kURXNGoUetulTb5ow8BvD1gncOaYHSD0kbHZG+bLsUZDFatEr2KW8jbG</X509Certificate></X509Data></KeyInfo></KeyDescriptor>"
            + "<SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhost/Saml2/Logout\" />"
            + "<SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost/Saml2/Logout\" />"
            + "<NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>"
            + "<AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost/Saml2/Acs\" index=\"0\" isDefault=\"true\" />"
            + "<AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" Location=\"http://localhost/Saml2/Acs\" index=\"1\" isDefault=\"false\" />"
            + "<AttributeConsumingService index=\"0\" isDefault=\"true\">"
            + "<ServiceName xml:lang=\"en\">attributeServiceName</ServiceName>"
            + "<RequestedAttribute Name=\"urn:attributeName\" isRequired=\"true\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\" FriendlyName=\"friendlyName\">"
            + "<saml2:AttributeValue>value1</saml2:AttributeValue>"
            + "<saml2:AttributeValue>value2</saml2:AttributeValue>"
            + "</RequestedAttribute>"
            + "<RequestedAttribute Name=\"someName\" isRequired=\"false\" />"
            + "</AttributeConsumingService>"
            + "</SPSSODescriptor>"
            + "<Organization>"
            + "<OrganizationName xml:lang=\"\">Sustainsys.Saml2</OrganizationName>"
            + "<OrganizationDisplayName xml:lang=\"\">Sustainsys Saml2</OrganizationDisplayName>"
            + "<OrganizationURL xml:lang=\"\">http://github.com/SustainsysIT/Saml2</OrganizationURL>"
            + "</Organization>"
            + "<ContactPerson contactType=\"support\">"
            + "<Company>Sustainsys</Company>"
            + "<GivenName>Anders</GivenName>"
            + "<SurName>Abel</SurName>"
            + "<EmailAddress>info@Sustainsys.se</EmailAddress>"
            + "<EmailAddress>anders.abel@Sustainsys.se</EmailAddress>"
            + "<TelephoneNumber>+46 8 587 650 00</TelephoneNumber>"
            + "<TelephoneNumber>+46 708 96 50 63</TelephoneNumber>"
            + "</ContactPerson>"
            + "<ContactPerson contactType=\"technical\" />"
            + "</EntityDescriptor>";

            payloadXml.Should().BeEquivalentTo(XmlHelpers.XmlDocumentFromString(expectedXml));
            subject.ContentType.Should().Be("application/samlmetadata+xml");
        }

        [TestMethod]
        public void MetadataCommand_Run_MinimalMetadata()
        {
            var spOptions = new SPOptions()
            {
                EntityId = new EntityId("http://localhost/Saml2"),
            };
            var options = new Options(spOptions);

            var result = new MetadataCommand().Run(request, options);

            XDocument subject = XDocument.Parse(result.Content);

            // Ignore the ID attribute, it is just filled with a GUID that can't be easily tested.
            subject.Root.Attribute("ID").Remove();

            var expectedXml = new XDocument(new XElement(Saml2Namespaces.Saml2Metadata + "EntityDescriptor",
                new XAttribute("entityID", "http://localhost/Saml2"),
                new XAttribute("cacheDuration", "PT1H"),
                // Have to manually add the xmlns attribute here, as it will be present in the subject
                // data and the xml tree comparison will fail if it is not present in both. Just setting the 
                // namespace of the elements does not inject the xmlns attribute into the node tree. It is
                // only done when outputting a string.
                // See http://stackoverflow.com/questions/24156689/xnode-deepequals-unexpectedly-returns-false
                new XAttribute(XNamespace.Xmlns + "saml2", Saml2Namespaces.Saml2),
                new XAttribute("xmlns", Saml2Namespaces.Saml2MetadataName),
                new XElement(Saml2Namespaces.Saml2Metadata + "SPSSODescriptor",
                    new XAttribute("protocolSupportEnumeration", "urn:oasis:names:tc:SAML:2.0:protocol"),
                    new XElement(Saml2Namespaces.Saml2Metadata + "AssertionConsumerService",
                        new XAttribute("Binding", Saml2Binding.HttpPostUri),
                        new XAttribute("Location", "http://localhost/Saml2/Acs"),
                        new XAttribute("index", 0),
                        new XAttribute("isDefault", true)),
                    new XElement(Saml2Namespaces.Saml2Metadata + "AssertionConsumerService",
                        new XAttribute("Binding", Saml2Binding.HttpArtifactUri),
                        new XAttribute("Location", "http://localhost/Saml2/Acs"),
                        new XAttribute("index", 1),
                        new XAttribute("isDefault", false)))));

            subject.Should().BeEquivalentTo(expectedXml);
        }

        [TestMethod]
        public void MetadataCommand_Run_ThrowsOnMissingOrganizationDisplayName()
        {
            var options = StubFactory.CreateOptions();

            options.SPOptions.Organization.DisplayNames.Clear();

            Action a = () => new MetadataCommand().Run(request, options);

            a.ShouldThrow<MetadataSerializationException>().And.Message.Should().StartWith("ID3203");
        }

        [TestMethod]
        public void MetadataCommand_Run_CallsNotifications()
        {
            var request = new HttpRequestData("GET", new Uri("http://localhost/Saml2"));

            var options = StubFactory.CreateOptions();

            options.Notifications.MetadataCreated = (md, urls) =>
            {
                md.CacheDuration = new TimeSpan(0, 0, 17);
                urls.ApplicationUrl.Host.Should().Be("localhost");
            };

            CommandResult notifiedCommandResult = null;
            options.Notifications.MetadataCommandResultCreated = cr =>
            {
                notifiedCommandResult = cr;
            };

            var subject = new MetadataCommand();
            var actualCommandResult = subject.Run(request, options);
            actualCommandResult.Should().BeSameAs(notifiedCommandResult);

            var parsedResult = XElement.Parse(actualCommandResult.Content);
            parsedResult.Attribute("cacheDuration").Value
                .Should().Be("PT17S");
        }
    }
}
