using Sustainsys.Saml2.Exceptions;
using Sustainsys.Saml2.Internal;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using Sustainsys.Saml2.Tokens;
using System.IO.Compression;

namespace Sustainsys.Saml2.Metadata
{
    /// <summary>
    /// Helper for loading SAML2 metadata
    /// </summary>
    public static class MetadataLoader
    {
        /// <summary>
        /// Load and parse metadata.
        /// </summary>
        /// <param name="metadataLocation">Path to metadata. A Url, absolute
        /// path or an app relative path (e.g. ~/App_Data/metadata.xml)</param>
        /// <returns>EntityDescriptor containing metadata</returns>
        public static EntityDescriptor LoadIdp(string metadataLocation)
        {
            return LoadIdp(metadataLocation, false);
        }
        
        internal const string LoadIdpFoundEntitiesDescriptor = "Tried to load metadata for an IdentityProvider, which should be an <EntityDescriptor>, but found an <EntitiesDescriptor>. To load that metadata you should use the Federation configuration and not an IdentityProvider. You can also set the SPOptions.Compatibility.UnpackEntitiesDescriptorInIdentityProviderMetadata option to true.";
        internal const string LoadIdpUnpackingFoundMultipleEntityDescriptors = "Unpacked an EntitiesDescriptor when loading idp metadata, but found multiple EntityDescriptors.Unpacking is only supported if the metadata contains a single EntityDescriptor. Maybe you should use a Federation instead of configuring a single IdentityProvider";

        /// <summary>
        /// Load and parse metadata.
        /// </summary>
        /// <param name="metadataLocation">Path to metadata. A Url, absolute
        /// path or an app relative path (e.g. ~/App_Data/metadata.xml)</param>
        /// <param name="unpackEntitiesDescriptor">If the metadata contains
        /// an EntitiesDescriptor, try to unpack it and return a single
        /// EntityDescriptor inside if there is one.</param>
        /// <returns>EntityDescriptor containing metadata</returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "EntityDescriptors")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "SPOptions")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "UnpackEntitiesDescriptorInIdentityProviderMetadata")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "EntitiesDescriptor")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "EntityDescriptor")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "IdentityProvider")]
        public static EntityDescriptor LoadIdp(string metadataLocation, bool unpackEntitiesDescriptor)
        {
            if (metadataLocation == null)
            {
                throw new ArgumentNullException(nameof(metadataLocation));
            }

            var result = Load(metadataLocation, null, false, null);

            var entitiesDescriptor = result as EntitiesDescriptor;
            if(entitiesDescriptor != null)
            {
                if(unpackEntitiesDescriptor)
                {
                    if(entitiesDescriptor.ChildEntities.Count > 1)
                    {
                        throw new InvalidOperationException(LoadIdpUnpackingFoundMultipleEntityDescriptors);
                    }

                    return (EntityDescriptor)entitiesDescriptor.ChildEntities.Single();
                }

                throw new InvalidOperationException(LoadIdpFoundEntitiesDescriptor);
            }

            return (EntityDescriptor)result;
        }

        private static MetadataBase Load(
            string metadataLocation,
            IEnumerable<SecurityKeyIdentifierClause> signingKeys,
            bool validateCertificate,
            string minIncomingSigningAlgorithm)
        {
            if (metadataLocation.Length < 400)
            {
                if (PathHelper.IsWebRootRelative(metadataLocation))
                {
                    metadataLocation = PathHelper.MapPath(metadataLocation);
                }

                using (var client = new WebClient())
                using (var stream = client.OpenRead(metadataLocation))
                using (var ms = new MemoryStream())
                {
                    byte[] buf = new byte[65536];
                    for (; ; )
                    {
                        int read = stream.Read(buf, 0, buf.Length);
                        if (read == 0)
                            break;
                        ms.Write(buf, 0, read);
                    }
                    ms.Position = 0;
                    var reader = XmlDictionaryReader.CreateTextReader(
                        ms,
                        XmlDictionaryReaderQuotas.Max);

                    if (signingKeys != null)
                    {
                        reader = ValidateSignature(
                            reader,
                            signingKeys,
                            validateCertificate,
                            minIncomingSigningAlgorithm);
                    }

                    return Load(reader);
                }
            }
            //Location length is greater than 400 therefore needs to be loaded as stream
            byte[] gZipBuffer = Convert.FromBase64String(metadataLocation);
            var buffer = new byte[1];
            using (var memoryStream = new MemoryStream())
            {

                int dataLength = BitConverter.ToInt32(gZipBuffer, 0);
                memoryStream.Write(gZipBuffer, 4, gZipBuffer.Length - 4);
                buffer = new byte[dataLength];
                memoryStream.Position = 0;
                using (var gZipStream = new GZipStream(memoryStream, CompressionMode.Decompress))
                {
                    gZipStream.Read(buffer, 0, buffer.Length);
                }

                XmlDictionaryReader readerZipped = null;
                using (readerZipped = XmlDictionaryReader.CreateTextReader(buffer, XmlDictionaryReaderQuotas.Max))
                {
                    if (signingKeys != null)
                    {
                        readerZipped = ValidateSignature(
                            readerZipped,
                            signingKeys,
                            validateCertificate,
                            minIncomingSigningAlgorithm);
                    }

                    return Load(readerZipped);
                }
            }
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "No unmanaged resources involved, safe to ignore")]
        private static XmlDictionaryReader ValidateSignature(
            XmlDictionaryReader reader,
            IEnumerable<SecurityKeyIdentifierClause> signingKeys,
            bool validateCertificate,
            string minIncomingSigningAlgorithm)
        {
            var xmlDoc = XmlHelpers.CreateSafeXmlDocument();
            xmlDoc.Load(reader);

            if(!xmlDoc.DocumentElement.IsSignedByAny(
                signingKeys,
                validateCertificate,
                minIncomingSigningAlgorithm))
            {
                throw new InvalidSignatureException("Signature validation failed for federation metadata.");
            }

            return XmlDictionaryReader.CreateDictionaryReader(
                new XmlNodeReader(xmlDoc));
        }

        internal static MetadataBase Load(XmlDictionaryReader reader)
        {
            var serializer = ExtendedMetadataSerializer.ReaderInstance;
            
            // Filter out the signature from the metadata, as the built in MetadataSerializer
            // doesn't handle the XmlDsigNamespaceUrl http://www.w3.org/2000/09/xmldsig# which
            // is allowed (and for SAMLv1 even recommended).
            using (var filter = new FilteringXmlDictionaryReader(SignedXml.XmlDsigNamespaceUrl, "Signature", reader))
            {
                return serializer.ReadMetadata(filter);
            }
        }

        internal const string LoadFederationFoundEntityDescriptor = "Tried to load metadata for a Federation, which should be an <EntitiesDescriptor> containing one or more <EntityDescriptor> elements, but found an <EntityDescriptor>. To load that metadata you should use the IdentityProvider configuration and not a Federation.";

        /// <summary>
        /// Load and parse metadata for a federation.
        /// </summary>
        /// <param name="metadataLocation">Url to metadata</param>
        /// <returns>Extended entitiesdescriptor</returns>
        public static EntitiesDescriptor LoadFederation(string metadataLocation)
        {
            return LoadFederation(metadataLocation, null, false, null);
        }

        /// <summary>
        /// Load and parse metadata for a federation.
        /// </summary>
        /// <param name="metadataLocation">Url to metadata</param>
        /// <param name="signingKeys"></param>
        /// <param name="validateCertificate">Validate the certificate when doing
        /// signature validation. Normally a bad idea with SAML2 as certificates
        /// are not required to be valid but are only used as conventient carriers
        /// for keys.</param>
        /// <param name="minIncomingSigningAlgorithm">Mininum strength accepted
        /// for signing algorithm.</param>
        /// <returns>Extended entitiesdescriptor</returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "EntitiesDescriptor")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "EntityDescriptor")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "IdentityProvider")]
        public static EntitiesDescriptor LoadFederation(
            string metadataLocation,
            IEnumerable<SecurityKeyIdentifierClause> signingKeys,
            bool validateCertificate,
            string minIncomingSigningAlgorithm)
        {
            if (metadataLocation == null)
            {
                throw new ArgumentNullException(nameof(metadataLocation));
            }

            var result = Load(
                metadataLocation,
                signingKeys,
                validateCertificate,
                minIncomingSigningAlgorithm);

            if (result is EntityDescriptor)
            {
                throw new InvalidOperationException(LoadFederationFoundEntityDescriptor);
            }

            return (EntitiesDescriptor)result;
        }

    }
}
