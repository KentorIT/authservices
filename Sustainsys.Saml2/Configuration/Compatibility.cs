using System;

namespace Sustainsys.Saml2.Configuration
{
    /// <summary>
    /// Compatibility settings. Can be used to make Saml2 accept
    /// certain non-standard behaviour.
    /// </summary>
    public class Compatibility
    {
        /// <summary>
        /// Ctor
        /// </summary>
        public Compatibility()
        { }

        /// <summary>
        /// Ctor
        /// </summary>
        /// <param name="configElement">Config element to load</param>
        public Compatibility(CompatibilityElement configElement)
        {
            if(configElement == null)
            {
                throw new ArgumentNullException(nameof(configElement));
            }

            UnpackEntitiesDescriptorInIdentityProviderMetadata =
                configElement.UnpackEntitiesDescriptorInIdentityProviderMetadata;
            DisableLogoutStateCookie = configElement.DisableLogoutStateCookie;
            IgnoreMissingInResponseTo = configElement.IgnoreMissingInResponseTo;
            AcceptOneTimeUseAssertions = configElement.AcceptOneTimeUseAssertions;
        }

        /// <summary>
        /// If an EntitiesDescriptor element is found when loading metadata
        /// for an IdentityProvider, automatically check inside it if there
        /// is a single EntityDescriptor and in that case use it.
        /// </summary>
        public bool UnpackEntitiesDescriptorInIdentityProviderMetadata { get; set; }

        /// <summary>
        /// Do not send logout state cookie, e.g. if you are not using ReturnUrl
        /// or if you know the cookie will be lost due to cross-domain redirects
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage( "Microsoft.Naming", "CA1726:UsePreferredTerms", MessageId = "Logout" )]
        public bool DisableLogoutStateCookie { get; set; }

        /// <summary>
        /// Honor the owin authentication mode even on logout. Normally the logout
        /// handling is always done as if the middleware was active, to allow for
        /// simple sign out without specifying an auth type.
        /// </summary>
        public bool StrictOwinAuthenticationMode { get; set; }

        /// <summary>
        /// Do not read the AuthnContext element in Saml2Response.
        /// If you do not need these values to be present as claims in the generated
        /// identity, using this option can prevent XML format errors (ID0013)
        /// e.g. when value cannot parse as absolute URI
        /// </summary>
        public bool IgnoreAuthenticationContextInResponse { get; set; }

        /// <summary>
        /// Ignore the check for the missing InResponseTo attribute in the Saml response.
        /// This is different to setting the allowUnsolicitedAuthnResponse as it will only
        /// ignore the InResponseTo attribute if there is no relayState. Setting
        /// IgnoreMissingInResponseTo to true will always skip the check.
        /// </summary>
        public bool IgnoreMissingInResponseTo { get; set; }

        /// <summary>
        /// If a received SamlResponse is for one time use (Assertion/Conditions/OneTimeUse)
        /// this will allow it to be used for WebSSO.
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1702:CompoundWordsShouldBeCasedCorrectly", MessageId = "OneTime")]
        public bool AcceptOneTimeUseAssertions { get; set; }
    }
}
