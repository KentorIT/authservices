using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Sustainsys.Saml2.Metadata.Extensions
{
    internal static class AsymmetricAlgorithmExtensions
    {
        internal static AsymmetricAlgorithm GetSha256EnabledAsymmetricAlgorithm(
            this AsymmetricAlgorithm original)
        {
#if NETSTANDARD2_0
            return original;
#else
            // The provider is probably using the default ProviderType. That's
            // a problem, because it doesn't support SHA256. Let's do some
            // black magic and create a new provider of a type that supports
            // SHA256 without the user ever knowing we fix this. This is what
            // is done in X509AsymmetricKey.GetSignatureFormatter if
            // http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 isn't
            // a known algorithm, so users kind of expect this to be handled
            // for them magically.

            var provider = (RSACryptoServiceProvider)original;
            var cspParams = new CspParameters();
            cspParams.ProviderType = 24; //PROV_RSA_AES
            cspParams.KeyContainerName = provider.CspKeyContainerInfo.KeyContainerName;
            cspParams.KeyNumber = (int)provider.CspKeyContainerInfo.KeyNumber;
            SetMachineKeyFlag(provider, cspParams);

            cspParams.Flags |= CspProviderFlags.UseExistingKey;

            return new RSACryptoServiceProvider(cspParams);
#endif
        }

        // We don't want to use Machine Key store during tests, so let's
        // put this one in an own method that's not included in coverage metrics.
        [ExcludeFromCodeCoverage]
        private static void SetMachineKeyFlag(RSACryptoServiceProvider provider, CspParameters cspParams)
        {
            if (provider.CspKeyContainerInfo.MachineKeyStore)
            {
                cspParams.Flags = CspProviderFlags.UseMachineKeyStore;
            }
        }
    }
}