using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using Sustainsys.Saml2.Configuration;
using Sustainsys.Saml2.Metadata.Descriptors;
using Sustainsys.Saml2.Metadata.Services;
using Sustainsys.Saml2.Tokens;
using Sustainsys.Saml2.WebSso;

namespace Sustainsys.Saml2.Metadata
{
    public static class SPOptionsExtensions
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Maintainability", "CA1506:AvoidExcessiveClassCoupling")]
        public static EntityDescriptor CreateMetadata(this SPOptions spOptions, Saml2Urls urls)
        {
            var ed = new EntityDescriptor
            {
                EntityId = spOptions.EntityId,
                Organization = spOptions.Organization,
                CacheDuration = spOptions.MetadataCacheDuration,
            };

            if(spOptions.MetadataValidDuration.HasValue)
            {
                ed.ValidUntil = DateTime.UtcNow.Add(spOptions.MetadataValidDuration.Value);
            }

            foreach (var contact in spOptions.Contacts)
            {
                ed.Contacts.Add(contact);
            }

            var spsso = new SpSsoDescriptor()
            {
                WantAssertionsSigned = spOptions.WantAssertionsSigned,
                AuthnRequestsSigned = spOptions.AuthenticateRequestSigningBehavior == SigningBehavior.Always
            };

            spsso.ProtocolsSupported.Add(new Uri("urn:oasis:names:tc:SAML:2.0:protocol"));

            spsso.AssertionConsumerServices.Add(0, new AssertionConsumerService()
            {
                Index = 0,
                IsDefault = true,
                Binding = Saml2Binding.HttpPostUri,
                Location = urls.AssertionConsumerServiceUrl
            });

            spsso.AssertionConsumerServices.Add(1, new AssertionConsumerService()
            {
                Index = 1,
                IsDefault = false,
                Binding = Saml2Binding.HttpArtifactUri,
                Location = urls.AssertionConsumerServiceUrl
            });

            foreach(var attributeService in spOptions.AttributeConsumingServices)
            {
                spsso.AttributeConsumingServices.Add(attributeService.Index, attributeService);
            }

            if (spOptions.ServiceCertificates != null)
            {
                var publishCertificates = spOptions.MetadataCertificates;
                foreach (var serviceCert in publishCertificates)
                {
					var x509Data = new X509Data();
					x509Data.Certificates.Add(serviceCert.Certificate);
					var keyInfo = new DSigKeyInfo();
					keyInfo.Data.Add(x509Data);

                    spsso.Keys.Add(
                        new KeyDescriptor
                        {
                            Use = (KeyType)(byte)serviceCert.Use,
                            KeyInfo = keyInfo
                        }
                    );
                }
            }

            if(spOptions.SigningServiceCertificate != null)
            {
                spsso.SingleLogoutServices.Add(new SingleLogoutService(
                    Saml2Binding.HttpRedirectUri, urls.LogoutUrl));
                
                if(spOptions.Compatibility.EnableLogoutOverPost)
                {
                    spsso.SingleLogoutServices.Add(new SingleLogoutService(
                        Saml2Binding.HttpPostUri, urls.LogoutUrl));
                }
            }

            if (spOptions.DiscoveryServiceUrl != null
                && !string.IsNullOrEmpty(spOptions.DiscoveryServiceUrl.OriginalString))
            {
                spsso.DiscoveryResponses.Add(0, new DiscoveryResponse
                {
                    Binding = Saml2Binding.DiscoveryResponseUri,
                    Index = 0,
                    IsDefault = true,
                    Location = urls.SignInUrl
                });
            }

            ed.RoleDescriptors.Add(spsso);

            return ed;
        }
    }
}
