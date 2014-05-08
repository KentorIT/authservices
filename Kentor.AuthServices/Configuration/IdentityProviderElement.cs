﻿using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;

namespace Kentor.AuthServices.Configuration
{
    /// <summary>
    /// Config element for the identity provider element.
    /// </summary>
    public class IdentityProviderElement : ConfigurationElement
    {
        private bool isReadOnly = true;

        internal void AllowConfigEdit(bool allow)
        {
            isReadOnly = !allow;
        }

        /// <summary>
        /// Allows local modification of the configuration for testing purposes
        /// </summary>
        /// <returns></returns>
        public override bool IsReadOnly()
        {
            return isReadOnly;
        }

        
        /// <summary>
        /// Issuer as presented by the idp. Used as key to configuration.
        /// </summary>
        [ConfigurationProperty("issuer", IsRequired = true)]
        public string Issuer
        {
            get
            {
                return (string)base["issuer"];
            }
        }

        /// <summary>
        /// Destination url to send requests to.
        /// </summary>
        [ConfigurationProperty("destinationUri", IsRequired = true)]
        public Uri DestinationUri
        {
            get
            {
                return (Uri)base["destinationUri"];
            }
        }

        /// <summary>
        /// The binding to use when sending requests to the Idp.
        /// </summary>
        [ConfigurationProperty("binding", IsRequired = true)]
        public Saml2BindingType Binding
        {
            get
            {
                return (Saml2BindingType)base["binding"];
            }
        }

        /// <summary>
        /// Certificate location for the certificate the Idp uses to sign its messages.
        /// </summary>
        [ConfigurationProperty("signingCertificate", IsRequired = true)]
        public CertificateElement SigningCertificate
        {
            get
            {
                return (CertificateElement)base["signingCertificate"];
            }
        }

        /// <summary>
        /// Certificate location for the certificate the Idp uses to sign its messages.
        /// </summary>
        [ConfigurationProperty("allowUnsolicitedAuthnResponse", IsRequired = true)]
        public bool AllowUnsolicitedAuthnResponse 
        {
            get
            {
                return (bool)base["allowUnsolicitedAuthnResponse"];
            }
            internal set
            {
                base["allowUnsolicitedAuthnResponse"] = value;
            }
        }
    }
}
