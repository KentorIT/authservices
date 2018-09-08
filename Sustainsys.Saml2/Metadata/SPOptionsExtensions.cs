using System;
using System.Collections.Generic;
using System.IdentityModel.Metadata;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using Sustainsys.Saml2.Configuration;
using Sustainsys.Saml2.WebSso;
using System.IdentityModel.Tokens;

namespace Sustainsys.Saml2.Metadata
{
    static class SPOptionsExtensions
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Maintainability", "CA1506:AvoidExcessiveClassCoupling")]
        public static ExtendedEntityDescriptor CreateMetadata(this SPOptions spOptions, Saml2Urls urls)
        {
            var ed = new ExtendedEntityDescriptor
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

            var spsso = new ExtendedServiceProviderSingleSignOnDescriptor()
            {
                WantAssertionsSigned = spOptions.WantAssertionsSigned,
                AuthenticationRequestsSigned = spOptions.AuthenticateRequestSigningBehavior == SigningBehavior.Always
            };

            spsso.ProtocolsSupported.Add(new Uri("urn:oasis:names:tc:SAML:2.0:protocol"));

            spsso.AssertionConsumerServices.Add(0, new IndexedProtocolEndpoint()
            {
                Index = 0,
                IsDefault = true,
                Binding = Saml2Binding.HttpPostUri,
                Location = urls.AssertionConsumerServiceUrl
            });

            spsso.AssertionConsumerServices.Add(1, new IndexedProtocolEndpoint()
            {
                Index = 1,
                IsDefault = false,
                Binding = Saml2Binding.HttpArtifactUri,
                Location = urls.AssertionConsumerServiceUrl
            });

            foreach(var attributeService in spOptions.AttributeConsumingServices)
            {
                spsso.AttributeConsumingServices.Add(attributeService);
            }

            if (spOptions.ServiceCertificates != null)
            {
                var publishCertificates = spOptions.MetadataCertificates;
                foreach (var serviceCert in publishCertificates)
                {
                    using (var securityToken = new X509SecurityToken(serviceCert.Certificate))
                    {
                        spsso.Keys.Add(
                            new KeyDescriptor
                            {
                                Use = (KeyType)(byte)serviceCert.Use,
                                KeyInfo = new SecurityKeyIdentifier(securityToken.CreateKeyIdentifierClause<X509RawDataKeyIdentifierClause>())
                            }
                        );
                    }
                }
            }

            if(spOptions.SigningServiceCertificate != null)
            {
                spsso.SingleLogoutServices.Add(new ProtocolEndpoint(
                    Saml2Binding.HttpRedirectUri, urls.LogoutUrl));
                spsso.SingleLogoutServices.Add(new ProtocolEndpoint(
                    Saml2Binding.HttpPostUri, urls.LogoutUrl));
            }

            if (spOptions.DiscoveryServiceUrl != null
                && !string.IsNullOrEmpty(spOptions.DiscoveryServiceUrl.OriginalString))
            {
                spsso.Extensions.DiscoveryResponse = new IndexedProtocolEndpoint
                {
                    Binding = Saml2Binding.DiscoveryResponseUri,
                    Index = 0,
                    IsDefault = true,
                    Location = urls.SignInUrl
                };
            }

            if (spOptions.NameIdPolicy != null
                && spOptions.NameIdPolicy.AllowCreate.GetValueOrDefault())
            {
                spsso.NameIdentifierFormats.Add(spOptions.NameIdPolicy.Format.GetUri());
            }

            ed.RoleDescriptors.Add(spsso);

            return ed;
        }
    }
}
