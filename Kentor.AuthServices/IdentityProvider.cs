using System.Collections.Generic;
using Kentor.AuthServices.Configuration;
using System;
using System.Configuration;
using System.Globalization;
using System.IdentityModel.Metadata;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using Kentor.AuthServices.Internal;
using Kentor.AuthServices.Metadata;
using Kentor.AuthServices.Saml2P;
using Kentor.AuthServices.WebSso;
using System.Threading.Tasks;
using System.Net;
using System.Collections.Concurrent;
using System.Security.Claims;

namespace Kentor.AuthServices
{
    /// <summary>
    /// Represents a known identity provider that this service provider can communicate with.
    /// </summary>
    public class IdentityProvider
    {
        /// <summary>
        /// Ctor
        /// </summary>
        /// <param name="entityId">Entity id of the identityprovider.</param>
        /// <param name="spOptions">Service provider options to use when 
        /// creating AuthnRequests for this Idp.</param>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "sp")]
        public IdentityProvider(EntityId entityId, SPOptions spOptions)
        {
            EntityId = entityId;
            this.spOptions = spOptions;
        }

        readonly SPOptions spOptions;

        internal IdentityProvider(IdentityProviderElement config, SPOptions spOptions)
        {
            singleSignOnServiceUrl = config.SignOnUrl;
            SingleLogoutServiceUrl = config.LogoutUrl;
            EntityId = new EntityId(config.EntityId);
            binding = config.Binding;
            AllowUnsolicitedAuthnResponse = config.AllowUnsolicitedAuthnResponse;
            metadataLocation = string.IsNullOrEmpty(config.MetadataLocation)
                ? null : config.MetadataLocation;
            WantAuthnRequestsSigned = config.WantAuthnRequestsSigned;
            DisableOutboundLogoutRequests = config.DisableOutboundLogoutRequests;

            var certificate = config.SigningCertificate.LoadCertificate();
            if (certificate != null)
            {
                signingKeys.AddConfiguredKey(
                    new X509RawDataKeyIdentifierClause(certificate));
            }

            foreach (var ars in config.ArtifactResolutionServices)
            {
                ArtifactResolutionServiceUrls[ars.Index] = ars.Location;
            }

            // If configured to load metadata, this will immediately do the load.
            this.spOptions = spOptions;
            LoadMetadata = config.LoadMetadata;

            // Validate if values are only from config. If metadata is loaded, validation
            // is done on metadata load.
            if (!LoadMetadata)
            {
                Validate();
            }
        }

        private void Validate()
        {
            if (Binding == 0)
            {
                throw new ConfigurationErrorsException("Missing binding configuration on Idp " + EntityId.Id + ".");
            }

            if (!SigningKeys.Any())
            {
                throw new ConfigurationErrorsException("Missing signing certificate configuration on Idp " + EntityId.Id + ".");
            }

            if (SingleSignOnServiceUrl == null)
            {
                throw new ConfigurationErrorsException("Missing assertion consumer service url configuration on Idp " + EntityId.Id + ".");
            }
        }

        private bool loadMetadata;

        /// <summary>
        /// Should this idp load metadata? The metadata is loaded immediately
        /// when the property is set to true, so the <see cref="MetadataLocation"/>
        /// must be correct before settingLoadMetadata to true.</summary>
        public bool LoadMetadata
        {
            get
            {
                return loadMetadata;
            }
            set
            {
                loadMetadata = value;
                if (loadMetadata)
                {
                    try
                    {
                        DoLoadMetadata();
                        Validate();
                    }
                    catch (WebException)
                    {
                        // Ignore if metadata load failed, an automatic
                        // retry has been scheduled.
                    }
                }
            }
        }

        private Saml2BindingType binding;

        /// <summary>
        /// The binding used when sending AuthnRequests to the identity provider.
        /// </summary>
        public Saml2BindingType Binding
        {
            get
            {
                ReloadMetadataIfRequired();
                return binding;
            }
            set
            {
                binding = value;
            }
        }

        private Uri singleSignOnServiceUrl;

        /// <summary>
        /// The Url of the single sign on service. This is where the browser is redirected or
        /// where the post data is sent to when sending an AuthnRequest to the idp.
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1726:UsePreferredTerms", MessageId = "SignOn")]
        public Uri SingleSignOnServiceUrl
        {
            get
            {
                ReloadMetadataIfRequired();
                return singleSignOnServiceUrl;
            }
            set
            {
                singleSignOnServiceUrl = value;
            }
        }

        private IDictionary<int, Uri> artifactResolutionServiceUrls
            = new ConcurrentDictionary<int, Uri>();

        /// <summary>
        /// Artifact resolution endpoints on the idp.
        /// </summary>
        public IDictionary<int, Uri> ArtifactResolutionServiceUrls
        {
            get
            {
                ReloadMetadataIfRequired();
                return artifactResolutionServiceUrls;
            }
        }


        Uri singleLogoutServiceUrl;
        /// <summary>
        /// The Url of the single sign out service. This is where the browser
        /// is redirected or where the post data is sent to when sending a
        /// LogoutRequest to the idp.
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1726:UsePreferredTerms", MessageId = "Logout")]
        public Uri SingleLogoutServiceUrl
        {
            get
            {
                ReloadMetadataIfRequired();
                return singleLogoutServiceUrl;
            }
            set
            {
                singleLogoutServiceUrl = value;
            }
        }

        Uri singleLogoutServiceResponseUrl;
        /// <summary>
        /// The Url to send single logout responses to. Defaults to 
        /// SingleLogoutServiceUrl.
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1726:UsePreferredTerms", MessageId = "Logout")]
        public Uri SingleLogoutServiceResponseUrl
        {
            get
            {
                ReloadMetadataIfRequired();
                return singleLogoutServiceResponseUrl ?? SingleLogoutServiceUrl;
            }
        }

        private Saml2BindingType singleLogoutServiceBinding;
        /// <summary>
        /// Binding for the Single logout service. If not set, returns the
        /// same as the main binding (used for AuthnRequests)
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1726:UsePreferredTerms", MessageId = "Logout")]
        public Saml2BindingType SingleLogoutServiceBinding
        {
            get
            {
                ReloadMetadataIfRequired();
                return singleLogoutServiceBinding == 0
                    ? Binding
                    : singleLogoutServiceBinding;
            }
            set
            {
                singleLogoutServiceBinding = value;
            }
        }

        /// <summary>
        /// The Entity Id of the identity provider.
        /// </summary>
        public EntityId EntityId { get; private set; }

        /// <summary>
        /// Is this idp allowed to send unsolicited responses, i.e. idp initiated sign in?
        /// </summary>
        public bool AllowUnsolicitedAuthnResponse { get; set; }

        private string metadataLocation;

        /// <summary>
        /// Location of metadata for the Identity Provider. Automatically enables
        /// <see cref="LoadMetadata"/>. The location can be a URL, an absolute
        /// path to a local file or an app relative  path 
        /// (e.g. ~/App_Data/IdpMetadata.xml). By default the entity id is
        /// interpreted as the metadata location (which is a convention).
        /// </summary>
        public string MetadataLocation
        {
            get
            {
                return metadataLocation ?? EntityId.Id;
            }
            set
            {
                metadataLocation = value;
                LoadMetadata = true;
            }
        }

        /// <summary>
        /// Create an authenticate request aimed for this idp.
        /// </summary>
        /// <param name="authServicesUrls">Urls for AuthServices, used to populate fields
        /// in the created AuthnRequest</param>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "AuthenticateRequestSigningBehavior")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "ServiceCertificates")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "AuthenticateRequests")]
        public Saml2AuthenticationRequest CreateAuthenticateRequest(
            AuthServicesUrls authServicesUrls)
        {
            if (authServicesUrls == null)
            {
                throw new ArgumentNullException(nameof(authServicesUrls));
            }

            var authnRequest = new Saml2AuthenticationRequest()
            {
                DestinationUrl = SingleSignOnServiceUrl,
                AssertionConsumerServiceUrl = authServicesUrls.AssertionConsumerServiceUrl,
                Issuer = spOptions.EntityId,
                // For now we only support one attribute consuming service.
                AttributeConsumingServiceIndex = spOptions.AttributeConsumingServices.Any() ? 0 : (int?)null,
                NameIdPolicy = spOptions.NameIdPolicy,
                RequestedAuthnContext = spOptions.RequestedAuthnContext,
                Binding = this.Binding
            };

            if (spOptions.AuthenticateRequestSigningBehavior == SigningBehavior.Always
                || (spOptions.AuthenticateRequestSigningBehavior == SigningBehavior.IfIdpWantAuthnRequestsSigned
                && WantAuthnRequestsSigned))
            {
                if (spOptions.SigningServiceCertificate == null)
                {
                    throw new ConfigurationErrorsException(
                        string.Format(
                            CultureInfo.InvariantCulture,
                            "Idp \"{0}\" is configured for signed AuthenticateRequests, but ServiceCertificates configuration contains no certificate with usage \"Signing\" or \"Both\". To resolve this issue you can a) add a service certificate with usage \"Signing\" or \"Both\" (default if not specified is \"Both\") or b) Set the AuthenticateRequestSigningBehavior configuration property to \"Never\".",
                            EntityId.Id));
                }

                authnRequest.SigningCertificate = spOptions.SigningServiceCertificate;
            }

            return authnRequest;
        }

        /// <summary>
        /// Bind a Saml2AuthenticateRequest using the active binding of the idp,
        /// producing a CommandResult with the result of the binding.
        /// </summary>
        /// <param name="request">The AuthnRequest to bind.</param>
        /// <returns>CommandResult with the bound request.</returns>
        public CommandResult Bind(ISaml2Message request)
        {
            return Saml2Binding.Get(Binding).Bind(request);
        }

        private ConfiguredAndLoadedSigningKeysCollection signingKeys =
            new ConfiguredAndLoadedSigningKeysCollection();

        /// <summary>
        /// The public key of the idp that is used to verify signatures of responses/assertions.
        /// </summary>
        public ConfiguredAndLoadedSigningKeysCollection SigningKeys
        {
            get
            {
                ReloadMetadataIfRequired();
                return signingKeys;
            }
        }

        object metadataLoadLock = new object();

        private void DoLoadMetadata()
        {
            lock (metadataLoadLock)
            {
                try
                {
                    var metadata = MetadataLoader.LoadIdp(
                        MetadataLocation,
                        spOptions.Compatibility.UnpackEntitiesDescriptorInIdentityProviderMetadata);

                    ReadMetadata(metadata);
                }
                catch (WebException)
                {
                    MetadataValidUntil = DateTime.MinValue;
                    throw;
                }
            }
        }

        /// <summary>
        /// Reads the supplied metadata and sets all properties of the 
        /// IdentityProvider based on the metadata.
        /// </summary>
        /// <param name="metadata">Metadata to read.</param>
        public void ReadMetadata(ExtendedEntityDescriptor metadata)
        {
            if (metadata == null)
            {
                throw new ArgumentNullException(nameof(metadata));
            }

            lock (metadataLoadLock)
            {
                if (metadata.EntityId.Id != EntityId.Id)
                {
                    var msg = string.Format(CultureInfo.InvariantCulture,
                        "Unexpected entity id \"{0}\" found when loading metadata for \"{1}\".",
                        metadata.EntityId.Id, EntityId.Id);
                    throw new ConfigurationErrorsException(msg);
                }

                ReadMetadataIdpDescriptor(metadata);

                MetadataValidUntil = metadata.CalculateMetadataValidUntil();
            }
        }

        private void ReadMetadataIdpDescriptor(ExtendedEntityDescriptor metadata)
        {
            var idpDescriptor = metadata.RoleDescriptors
                .OfType<IdentityProviderSingleSignOnDescriptor>().Single();

            WantAuthnRequestsSigned = idpDescriptor.WantAuthenticationRequestsSigned;

            var ssoService = GetPreferredEndpoint(idpDescriptor.SingleSignOnServices);
            if (ssoService != null)
            {
                binding = Saml2Binding.UriToSaml2BindingType(ssoService.Binding);
                singleSignOnServiceUrl = ssoService.Location;
            }

            var sloService = GetPreferredEndpoint(idpDescriptor.SingleLogoutServices);
            if (sloService != null)
            {
                SingleLogoutServiceUrl = sloService.Location;
                SingleLogoutServiceBinding = Saml2Binding.UriToSaml2BindingType(sloService.Binding);
                singleLogoutServiceResponseUrl = sloService.ResponseLocation;
            }

            foreach (var ars in idpDescriptor.ArtifactResolutionServices)
            {
                artifactResolutionServiceUrls[ars.Value.Index] = ars.Value.Location;
            }

            foreach (var ars in artifactResolutionServiceUrls.Keys
                .Where(k => !idpDescriptor.ArtifactResolutionServices.Keys.Contains(k)))
            {
                artifactResolutionServiceUrls.Remove(ars);
            }

            var keys = idpDescriptor.Keys.Where(k => k.Use == KeyType.Unspecified || k.Use == KeyType.Signing);

            signingKeys.SetLoadedItems(keys.Select(k => k.KeyInfo.First(c => c.CanCreateKey)).ToList());
        }

        private static ProtocolEndpoint GetPreferredEndpoint(ICollection<ProtocolEndpoint> endpoints)
        {
            // Prefer an endpoint with a redirect binding, then check for POST which 
            // is the other supported by AuthServices.
            return endpoints.FirstOrDefault(s => s.Binding == Saml2Binding.HttpRedirectUri) ??
                endpoints.FirstOrDefault(s => s.Binding == Saml2Binding.HttpPostUri);
        }

        private DateTime? metadataValidUntil;

        /// <summary>
        /// Validity time of the metadata this idp was configured from. Null if
        /// idp was not configured from metadata.
        /// </summary>
        public DateTime? MetadataValidUntil
        {
            get
            {
                return metadataValidUntil;
            }
            private set
            {
                metadataValidUntil = value;

                if (LoadMetadata)
                {
                    Task.Delay(MetadataRefreshScheduler.GetDelay(value.Value))
                        .ContinueWith((_) => DoLoadMetadata());
                }
            }
        }

        /// <summary>
        /// Does this Idp want the AuthnRequests signed?
        /// </summary>
        public bool WantAuthnRequestsSigned { get; set; }

        private void ReloadMetadataIfRequired()
        {
            if (LoadMetadata && MetadataValidUntil.Value < DateTime.UtcNow)
            {
                lock (metadataLoadLock)
                {
                    DoLoadMetadata();
                }
            }
        }

        /// <summary>
        /// Create a logout request to the idp, for the current identity.
        /// </summary>
        /// <returns></returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "serviceCertificates")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "ServiceCertificates")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "ISPOptions")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1726:UsePreferredTerms", MessageId = "Logout")]
        public Saml2LogoutRequest CreateLogoutRequest(ClaimsPrincipal user)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));
            if (spOptions.SigningServiceCertificate == null)
            {
                throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture,
                    "Tried to issue single logout request to {0}, but no signing certificate for the SP is configured and single logout requires signing. Add a certificate to the ISPOptions.ServiceCertificates collection, or to <serviceCertificates> element if you're using web.config.",
                    EntityId.Id));
            }

            return new Saml2LogoutRequest()
            {
                DestinationUrl = SingleLogoutServiceUrl,
                Issuer = spOptions.EntityId,
                NameId = user.FindFirst(AuthServicesClaimTypes.LogoutNameIdentifier)
                            .ToSaml2NameIdentifier(),
                SessionIndex =
                    user.FindFirst(AuthServicesClaimTypes.SessionIndex).Value,
                SigningCertificate = spOptions.SigningServiceCertificate,
            };
        }

        /// <summary>
        /// Disable outbound logout requests to this idp, even though
        /// AuthServices is configured for single logout and the idp supports
        /// it. This setting might be usable when adding SLO to an existing
        /// setup, to ensure that everyone is ready for SLO before activating.
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1726:UsePreferredTerms", MessageId = "Logout")]
        public bool DisableOutboundLogoutRequests { get; set; }
    }
}
