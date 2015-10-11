﻿using System.IO;
using System.IdentityModel.Metadata;
using System.Runtime.Serialization.Formatters.Binary;
using System.Web.Security;
using Kentor.AuthServices.Configuration;
using Kentor.AuthServices.WebSso;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace Kentor.AuthServices.HttpModule
{
    /// <summary>
    /// Extension methods to CommandResult to update a HttpResponseBase.
    /// </summary>
    public static class CommandResultHttpExtension
    {
        /// <summary>
        /// Apply the command result to a bare HttpResponse.
        /// </summary>
        /// <param name="commandResult">The CommandResult that will update the HttpResponse.</param>
        /// <param name="response">Http Response to write the result to.</param>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "HttpStatusCode")]
        public static void Apply(this CommandResult commandResult, HttpResponseBase response)
        {
            if (commandResult == null)
            {
                throw new ArgumentNullException("commandResult");
            }

            if (response == null)
            {
                throw new ArgumentNullException("response");
            }

            response.Cache.SetCacheability((HttpCacheability)commandResult.Cacheability);

            response.SetStoredRequestState(commandResult.StoredRequestState);

            if (commandResult.HttpStatusCode == HttpStatusCode.SeeOther || commandResult.Location != null)
            {
                if (commandResult.Location == null)
                {
                    throw new InvalidOperationException("Missing Location on redirect.");
                }
                if (commandResult.HttpStatusCode != HttpStatusCode.SeeOther)
                {
                    throw new InvalidOperationException("Invalid HttpStatusCode for redirect, but Location is specified");
                }

                response.Redirect(commandResult.Location.OriginalString);
            }
            else
            {
                response.StatusCode = (int)commandResult.HttpStatusCode;
                response.ContentType = commandResult.ContentType;
                response.Write(commandResult.Content);

                response.End();
            }
        }

        /// <summary>
        /// Establishes an application session by calling the session authentication module.
        /// </summary>
        [ExcludeFromCodeCoverage]
        public static void SignInSessionAuthenticationModule(this CommandResult commandResult)
        {
            if(commandResult == null)
            {
                throw new ArgumentNullException("commandResult");
            }

            // Ignore this if we're not running inside IIS, e.g. in unit tests.
            if (commandResult.Principal != null && HttpContext.Current != null)
            {
                var sessionToken = new SessionSecurityToken(commandResult.Principal);

                FederatedAuthentication.SessionAuthenticationModule
                    .AuthenticateSessionSecurityToken(sessionToken, true);
            }
        }
    }
}
