using Sustainsys.Saml2.Metadata.Descriptors;
using System.Xml;

namespace Sustainsys.Saml2.Metadata.Serialization
{
    public class ExtendedMetadataSerializer : MetadataSerializer
    {
        private ExtendedMetadataSerializer(SecurityTokenSerializer serializer)
            : base(serializer)
        { }

        private ExtendedMetadataSerializer()
        {
        }

        private static ExtendedMetadataSerializer readerInstance =
            new ExtendedMetadataSerializer();

        /// <summary>
        /// Use this instance for reading metadata. It uses custom extensions
        /// to increase feature support when reading metadata.
        /// </summary>
        public static ExtendedMetadataSerializer ReaderInstance
        {
            get
            {
                return readerInstance;
            }
        }

        private static ExtendedMetadataSerializer writerInstance =
            new ExtendedMetadataSerializer();

        public static ExtendedMetadataSerializer WriterInstance
        {
            get
            {
                return writerInstance;
            }
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1062:Validate arguments of public methods", MessageId = "0", Justification = "Method is only called by base class no validation needed.")]
        protected override void WriteCustomAttributes<T>(XmlWriter writer, T source)
        {
            if (typeof(T) == typeof(EntityDescriptor))
            {
                writer.WriteAttributeString("xmlns", "saml2", null, Saml2Namespaces.Saml2Name);
            }
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1062:Validate arguments of public methods", MessageId = "0")]
        protected override SpSsoDescriptor ReadSpSsoDescriptor(XmlReader reader)
        {
            reader.Skip();
            return CreateSpSsoDescriptorInstance();
        }

#if FALSE
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1062:Validate arguments of public methods", MessageId = "0")]
        protected override Organization ReadOrganization(XmlReader reader)
        {
            reader.Skip();
            return CreateOrganizationInstance();
        }
#endif
    }
}