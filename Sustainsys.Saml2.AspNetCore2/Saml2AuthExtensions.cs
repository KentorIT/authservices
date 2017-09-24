﻿using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Sustainsys.Saml2.AspNetCore2;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Extensions methods for adding Saml2 authentication
    /// </summary>
    public static class Saml2AuthExtensions
    {
        /// <summary>
        /// Register Saml2 Authentication with default scheme name.
        /// </summary>
        /// <param name="builder">Authentication Builder</param>
        /// <param name="options">Saml2 Options</param>
        /// <returns>Authentication Builder</returns>
        public static AuthenticationBuilder AddSaml2(
            this AuthenticationBuilder builder,
            Action<Saml2Options> options)
        {
            if(builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<Saml2Options>, PostConfigureSaml2Options>());

            return builder.AddRemoteScheme<Saml2Options, Saml2Handler>(
                Saml2Defaults.Scheme,
                Saml2Defaults.DisplayName,
                options);
        }
    }
}
