﻿using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IdentityModel.Metadata;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using Kentor.AuthServices.Configuration;

namespace Kentor.AuthServices
{
    class IdentityProvider
    {
        private static readonly IDictionary<EntityId, IdentityProvider> configuredIdentityProviders =
            KentorAuthServicesSection.Current.IdentityProviders.ToDictionary(
                idp => new EntityId(idp.EntityId),
                idp => new IdentityProvider(idp),
                EntityIdEqualityComparer.Instance);

        public class ActiveIdentityProvidersMap : IEnumerable<IdentityProvider>
        {
            private readonly IDictionary<EntityId, IdentityProvider> configuredIdps;
            private readonly IList<Federation> configuredFederations;

            internal ActiveIdentityProvidersMap(
                IDictionary<EntityId, IdentityProvider> configuredIdps,
                IList<Federation> configuredFederations)
            {
                this.configuredIdps = configuredIdps;
                this.configuredFederations = configuredFederations;
            }

            public IdentityProvider this[EntityId entityId]
            {
                get
                {
                    IdentityProvider idp;
                    if (TryGetValue(entityId, out idp))
                    {
                        return idp;
                    }
                    else 
                    {
                        throw new KeyNotFoundException("No Idp with entity id \"" + entityId.Id + "\" found.");
                    }
                }
            }

            public bool TryGetValue(EntityId entityId, out IdentityProvider idp)
            {
                if(configuredIdps.TryGetValue(entityId, out idp))
                {
                    return true;
                }

                foreach(var federation in configuredFederations)
                {
                    if(federation.IdentityProviders.TryGetValue(entityId, out idp))
                    {
                        return true;
                    }
                }

                if (DynamicIdentityProviders().TryGetValue(entityId, out idp))
                {
                    return true;
                }

                return false;
            }

            public IEnumerator<IdentityProvider> GetEnumerator()
            {
                return configuredIdps.Values
                    .Union(configuredFederations
                        .SelectMany(f => f.IdentityProviders.Select(i => i.Value)))
                    .Union(DynamicIdentityProviders().Values)
                .GetEnumerator();
            }

            [ExcludeFromCodeCoverage]
            System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
            {
                throw new NotImplementedException();
            }

            internal static DateTime lastFederationLoad = DateTime.MinValue;
            private static IDictionary<EntityId, IdentityProvider> dynamicIdentityProviders =
                new Dictionary<EntityId, IdentityProvider>();
            private static IFederationManager federationManager;

            private static IDictionary<EntityId, IdentityProvider> DynamicIdentityProviders()
            {
                if (string.IsNullOrWhiteSpace(KentorAuthServicesSection.Current.FederationManager) ||
                    DateTime.Now.Subtract(lastFederationLoad).TotalSeconds <
                    KentorAuthServicesSection.Current.MetadataCacheDuration)
                {
                    return dynamicIdentityProviders;
                }

                lastFederationLoad = DateTime.Now;

                Type federationManagerType;
                if (federationManager == null &&
                    (federationManagerType = Type.GetType(KentorAuthServicesSection.Current.FederationManager)) != null)
                {
                    federationManager = (IFederationManager)Activator.CreateInstance(federationManagerType);
                }

                if (federationManager == null)
                {
                    return dynamicIdentityProviders;
                }

                var dynamic = federationManager.Load();
                var dynamicProviders = dynamic.ChildEntities.Select(
                        f => new IdentityProvider(f, federationManager.AllowUnsolicitedAuthnResponse))
                        .ToDictionary(
                    idp => new EntityId(idp.EntityId.Id),
                    EntityIdEqualityComparer.Instance);

                dynamicIdentityProviders = dynamicProviders;

                return dynamicIdentityProviders;
            }
        }

        private static readonly ActiveIdentityProvidersMap activeIdentityProviders = 
            new ActiveIdentityProvidersMap(
                configuredIdentityProviders,
                KentorAuthServicesSection.Current.Federations.Select(
                f => new Federation(f.MetadataUrl, f.AllowUnsolicitedAuthnResponse)).ToList());

        public static ActiveIdentityProvidersMap ActiveIdentityProviders
        {
            get
            {
                return activeIdentityProviders;
            }
        }

        // Ctor used for testing.
        internal IdentityProvider(Uri destinationUri)
        {
            AssertionConsumerServiceUrl = destinationUri;
        }

        internal IdentityProvider(IdentityProviderElement config)
        {
            AssertionConsumerServiceUrl = config.DestinationUri;
            EntityId = new EntityId(config.EntityId);
            Binding = config.Binding;
            AllowUnsolicitedAuthnResponse = config.AllowUnsolicitedAuthnResponse;

            var certificate = config.SigningCertificate.LoadCertificate();

            if (certificate != null)
            {
                SigningKey = certificate.PublicKey.Key;
            }

            if (config.LoadMetadata)
            {
                LoadMetadata();
            }

            Validate();
        }

        internal IdentityProvider(EntityDescriptor metadata, bool allowUnsolicitedAuthnResponse)
        {
            AllowUnsolicitedAuthnResponse = allowUnsolicitedAuthnResponse;

            LoadMetadata(metadata);

            Validate();
        }

        private void Validate()
        {
            if(Binding == 0)
            {
                throw new ConfigurationErrorsException("Missing binding configuration on Idp " + EntityId.Id + ".");
            }

            if(SigningKey == null)
            {
                throw new ConfigurationErrorsException("Missing signing certificate configuration on Idp " + EntityId.Id + ".");
            }

            if (AssertionConsumerServiceUrl == null)
            {
                throw new ConfigurationErrorsException("Missing assertion consumer service url configuration on Idp " + EntityId.Id + ".");
            }
        }

        public Saml2BindingType Binding { get; private set; }

        public Uri AssertionConsumerServiceUrl { get; private set; }

        public EntityId EntityId { get; private set; }

        public bool AllowUnsolicitedAuthnResponse { get; private set; }

        public Saml2AuthenticationRequest CreateAuthenticateRequest(Uri returnUri)
        {
            var request = new Saml2AuthenticationRequest()
            {
                DestinationUri = AssertionConsumerServiceUrl,
                AssertionConsumerServiceUrl = KentorAuthServicesSection.Current.AssertionConsumerServiceUrl,
                Issuer = KentorAuthServicesSection.Current.EntityId
            };

            var responseData = new StoredRequestState(EntityId, returnUri);

            PendingAuthnRequests.Add(new Saml2Id(request.Id), responseData);

            return request;
        }

        public CommandResult Bind(Saml2AuthenticationRequest request)
        {
            return Saml2Binding.Get(Binding).Bind(request);
        }

        public AsymmetricAlgorithm SigningKey { get; private set; }

        private void LoadMetadata()
        {
            // So far only support for metadata at well known location.
            var metadata = MetadataLoader.LoadIdp(new Uri(EntityId.Id));

            LoadMetadata(metadata);
        }

        private void LoadMetadata(EntityDescriptor metadata)
        {
            if (EntityId != null)
            {
                if (metadata.EntityId.Id != EntityId.Id)
                {
                    var msg = string.Format(CultureInfo.InvariantCulture,
                        "Unexpected entity id \"{0}\" found when loading metadata for \"{1}\".",
                        metadata.EntityId.Id, EntityId.Id);
                    throw new ConfigurationErrorsException(msg);
                }
            }
            else
            {
                EntityId = metadata.EntityId;
            }

            var idpDescriptor = metadata.RoleDescriptors
                .OfType<IdentityProviderSingleSignOnDescriptor>().Single();

            var ssoService = idpDescriptor.SingleSignOnServices.First();

            Binding = Saml2Binding.UriToSaml2BindingType(ssoService.Binding);
            AssertionConsumerServiceUrl = ssoService.Location;

            var key = idpDescriptor.Keys
                .Where(k => k.Use == KeyType.Unspecified || k.Use == KeyType.Signing)
                .SingleOrDefault();

            if (key != null)
            {
                SigningKey = ((AsymmetricSecurityKey)key.KeyInfo.CreateKey())
                    .GetAsymmetricAlgorithm(SignedXml.XmlDsigRSASHA1Url, false);
            }
        }
    }
}
