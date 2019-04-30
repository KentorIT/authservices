using System.Collections.Generic;
using Sustainsys.Saml2.Configuration;
using System;
using System.Configuration;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using Sustainsys.Saml2.Internal;
using Sustainsys.Saml2.Metadata;
using Sustainsys.Saml2.Saml2P;
using Sustainsys.Saml2.WebSso;
using System.Threading.Tasks;
using System.Net;
using System.Collections.Concurrent;
using System.Security.Claims;
using System.Diagnostics.CodeAnalysis;
using Sustainsys.Saml2.Tokens;

namespace Sustainsys.Saml2
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
            if (spOptions == null)
            {
                throw new ArgumentNullException(nameof(spOptions));
            }

            EntityId = entityId;
            this.spOptions = spOptions;
            OutboundSigningAlgorithm = spOptions.OutboundSigningAlgorithm;
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

            OutboundSigningAlgorithm = string.IsNullOrEmpty(config.OutboundSigningAlgorithm) ?
                spOptions.OutboundSigningAlgorithm :
                XmlHelpers.GetFullSigningAlgorithmName(config.OutboundSigningAlgorithm);

            foreach (var ars in config.ArtifactResolutionServices)
            {
                ArtifactResolutionServiceUrls[ars.Index] = ars.Location;
            }

            // If configured to load metadata, this will immediately do the load.
            this.spOptions = spOptions;
            LoadMetadata = config.LoadMetadata || !string.IsNullOrEmpty(config.MetadataLocation);

            // Validate if values are only from config. If metadata is loaded, validation
            // is done on metadata load.
            if (!LoadMetadata)
            {
                Validate();
            }

            RelayStateUsedAsReturnUrl = config.RelayStateUsedAsReturnUrl;
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
            set
            {
                singleLogoutServiceResponseUrl = value;
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

        /// <summary>
        /// Does the RelayState contains the return url?, 
        /// This setting is used only when the AllowUnsolicitedAuthnResponse setting is enabled.
        /// </summary>
        public bool RelayStateUsedAsReturnUrl { get; set; }

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
        /// <param name="saml2Urls">Urls for Saml2, used to populate fields
        /// in the created AuthnRequest</param>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "AuthenticateRequestSigningBehavior")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "ServiceCertificates")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "AuthenticateRequests")]
        public Saml2AuthenticationRequest CreateAuthenticateRequest(
            Saml2Urls saml2Urls)
        {
            if (saml2Urls == null)
            {
                throw new ArgumentNullException(nameof(saml2Urls));
            }

            var authnRequest = new Saml2AuthenticationRequest()
            {
                DestinationUrl = SingleSignOnServiceUrl,
                AssertionConsumerServiceUrl = saml2Urls.AssertionConsumerServiceUrl,
                Issuer = spOptions.EntityId,
                IssuerFormat = spOptions.EntityFormat,
                IssuerNameQualifier = spOptions.EntityNameQualifier,
                // For now we only support one attribute consuming service.
                AttributeConsumingServiceIndex = spOptions.AttributeConsumingServices.Any() ? 0 : (int?)null,
                NameIdPolicy = spOptions.NameIdPolicy,
                RequestedAuthnContext = spOptions.RequestedAuthnContext,
                SigningAlgorithm = this.OutboundSigningAlgorithm
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
        /// Signing Algorithm to be used when signing oubound messages.
        /// </summary>
        public string OutboundSigningAlgorithm { get; set; }

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
            if (LoadMetadata)
            {
                lock (metadataLoadLock)
                {
                    try
                    {
                        spOptions.Logger?.WriteInformation("Loading metadata for idp " + EntityId.Id);
                        var metadata = MetadataLoader.LoadIdp(
                            MetadataLocation,
                            spOptions.Compatibility.UnpackEntitiesDescriptorInIdentityProviderMetadata);

                        ReadMetadata(metadata);
                    }
                    catch (WebException ex)
                    {
                        spOptions.Logger?.WriteError("Failed to load metadata for idp " + EntityId.Id, ex);
                        MetadataValidUntil = DateTime.MinValue;
                        throw;
                    }
                }
            }
        }

        /// <summary>
        /// Reads the supplied metadata and sets all properties of the 
        /// IdentityProvider based on the metadata.
        /// </summary>
        /// <param name="metadata">Metadata to read.</param>
        public void ReadMetadata(EntityDescriptor metadata)
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

        private void ReadMetadataIdpDescriptor(EntityDescriptor metadata)
        {
            var idpDescriptor = metadata.RoleDescriptors
                .OfType<IdpSsoDescriptor>().Single();

            WantAuthnRequestsSigned = idpDescriptor.WantAuthnRequestsSigned ?? false;

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

            foreach (var kv in idpDescriptor.ArtifactResolutionServices)
            {
				var ars = kv.Value;
                artifactResolutionServiceUrls[ars.Index] = ars.Location;
            }

			var arsKeys = idpDescriptor.ArtifactResolutionServices.ToLookup(x => x.Value.Index);
            foreach (var ars in artifactResolutionServiceUrls.Keys
                .Where(k => !arsKeys.Contains(k)))
            {
                artifactResolutionServiceUrls.Remove(ars);
            }

            var keys = idpDescriptor.Keys.Where(k => k.Use == KeyType.Unspecified || k.Use == KeyType.Signing);

            signingKeys.SetLoadedItems(keys.Select(k => k.KeyInfo
				.MakeSecurityKeyIdentifier().First(c => c.CanCreateKey)).ToList());
        }

        private static T GetPreferredEndpoint<T>(ICollection<T> endpoints) where T : Endpoint
        {
            // Prefer an endpoint with a redirect binding, then check for POST which 
            // is the other supported by Saml2.
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
                    ScheduleMetadataRefresh();
                }
            }
        }

        private void ScheduleMetadataRefresh()
        {
            // Use a weak reference to allow garbage collector to collect any
            // non-referenced IdentityProvider objects without the timer being
            // the thing that keeps it alive.
            var weakThis = new WeakReference<IdentityProvider>(this);

            Task.Delay(MetadataRefreshScheduler.GetDelay(MetadataValidUntil.Value))
                .ContinueWith((_) => DoLoadMetadataIfTargetAlive(weakThis));
        }

        // Exclude because we don't want to wait for a GC run during unit test run
        // to trigger the case when the Idp has been garbaged collected.
        [ExcludeFromCodeCoverage]
        private static void DoLoadMetadataIfTargetAlive(WeakReference<IdentityProvider> target)
        {
            IdentityProvider idp;
            if(target.TryGetTarget(out idp))
            {
                idp.DoLoadMetadata();
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
                IssuerFormat = spOptions.EntityFormat,
                IssuerNameQualifier = spOptions.EntityNameQualifier,
                NameId = user.FindFirst(Saml2ClaimTypes.LogoutNameIdentifier)
                            .ToSaml2NameIdentifier(),
                SessionIndex =
                    user.FindFirst(Saml2ClaimTypes.SessionIndex).Value,
                SigningCertificate = spOptions.SigningServiceCertificate,
                SigningAlgorithm = OutboundSigningAlgorithm
            };
        }

        /// <summary>
        /// Disable outbound logout requests to this idp, even though
        /// Saml2 is configured for single logout and the idp supports
        /// it. This setting might be usable when adding SLO to an existing
        /// setup, to ensure that everyone is ready for SLO before activating.
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1726:UsePreferredTerms", MessageId = "Logout")]
        public bool DisableOutboundLogoutRequests { get; set; }
    }
}
