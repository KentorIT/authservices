using System.Configuration;

namespace Sustainsys.Saml2.Configuration
{
    /// <summary>
    /// Compatibility settings. Can be used to make Saml2 accept
        /// certain non-standard behaviour.
    /// </summary>
    public class CompatibilityElement : ConfigurationElement
    {
        internal bool AllowChange { get; set; }

        /// <summary>
        /// Used for testing, always returns true in production.
        /// </summary>
        /// <returns>Returns true (unless during tests)</returns>
        public override bool IsReadOnly()
        {
            return !AllowChange;
        }

        const string unpackEntitiesDescriptorInIdentityProviderMetadata
            = nameof(unpackEntitiesDescriptorInIdentityProviderMetadata);

        /// <summary>
        /// If an EntitiesDescriptor element is found when loading metadata
        /// for an IdentityProvider, automatically check inside it if there
        /// is a single EntityDescriptor and in that case use it.
        /// </summary>
        [ConfigurationProperty(unpackEntitiesDescriptorInIdentityProviderMetadata, IsRequired = false)]
        public bool UnpackEntitiesDescriptorInIdentityProviderMetadata
        {
            get
            {
                return (bool)base[unpackEntitiesDescriptorInIdentityProviderMetadata];
            }
            set
            {
                base[unpackEntitiesDescriptorInIdentityProviderMetadata] = value;
            }
        }

        const string disableLogoutStateCookie = nameof(disableLogoutStateCookie);

        /// <summary>
        /// Do not send logout state cookie, e.g. if you are not using ReturnUrl
        /// or if you know the cookie will be lost due to cross-domain redirects
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1726:UsePreferredTerms", MessageId = "Logout")]
        [ConfigurationProperty(disableLogoutStateCookie, IsRequired = false)]
        public bool DisableLogoutStateCookie
        {
            get
            {
                return (bool)base[disableLogoutStateCookie];
            }
            set
            {
                base[disableLogoutStateCookie] = value;
            }
        }

        const string ignoreMissingInResponseTo = nameof(ignoreMissingInResponseTo);

        /// <summary>
        /// Ignore the check for the missing InResponseTo attribute in the Saml response.
        /// This is different to setting the allowUnsolicitedAuthnResponse as it will only
        /// ignore the InResponseTo attribute if there is no relayState. Setting
        /// IgnoreMissingInResponseTo to true will always skip the check.
        /// </summary>
        [ConfigurationProperty(ignoreMissingInResponseTo, IsRequired = false)]
        public bool IgnoreMissingInResponseTo
        {
            get
            {
                return (bool)base[ignoreMissingInResponseTo];
            }
            set
            {
                base[ignoreMissingInResponseTo] = value;
            }
        }

        const string acceptOneTimeUseAssertions = nameof(acceptOneTimeUseAssertions);

        /// <summary>
        /// If a received SamlResponse is for one time use (Assertion/Conditions/OneTimeUse)
        /// this will allow it to be used for WebSSO.
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1702:CompoundWordsShouldBeCasedCorrectly", MessageId = "OneTime")]
        [ConfigurationProperty(acceptOneTimeUseAssertions, IsRequired = false, DefaultValue = false)]
        public bool AcceptOneTimeUseAssertions
        {
            get
            {
                return (bool)base[acceptOneTimeUseAssertions];
            }
            set
            {
                base[acceptOneTimeUseAssertions] = value;
            }
        }
    }
}
