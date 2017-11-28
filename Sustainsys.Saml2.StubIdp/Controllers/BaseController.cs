﻿using System.IO;
using System.Net.Mime;
using Kentor.AuthServices.StubIdp.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Collections.Concurrent;
using System.Web;
using System.Web.Mvc;
using Kentor.AuthServices.Mvc;
using System.IdentityModel.Metadata;
using Kentor.AuthServices.Configuration;
using System.IdentityModel.Tokens;
using System.Configuration;
using Kentor.AuthServices.Saml2P;
using Kentor.AuthServices.WebSso;
using Kentor.AuthServices.HttpModule;
using Newtonsoft.Json.Schema;
using Newtonsoft.Json.Linq;
using System.Net;

namespace Kentor.AuthServices.StubIdp.Controllers
{
    public class BaseController : Controller
    {
        protected static ConcurrentDictionary<Guid, IdpConfigurationModel> cachedConfigurations = new ConcurrentDictionary<Guid, IdpConfigurationModel>();

        /// <summary>
        /// Special guid for the default IDP user list
        /// </summary>
        protected static readonly Guid defaultIdpGuid = Guid.Parse("e73d98ff-0f1c-4cc2-8808-6d1bf028a8a9");

        protected string GetIdpFileNamePath(Guid idpId)
        {
            if (idpId == defaultIdpGuid)
            {
                return Server.MapPath("~/App_Data/default.json");
            }
            else
            {
                return Server.MapPath(string.Format("~/App_Data/{0}.json", idpId));
            }
        }

        protected IdpConfigurationModel GetCachedConfiguration(Guid idpId)
        {
            IdpConfigurationModel newFileData = null;
            var fileData = cachedConfigurations.GetOrAdd(idpId, _ =>
            {
                var fileName = GetIdpFileNamePath(idpId);
                if (System.IO.File.Exists(fileName))
                {
                    newFileData = new IdpConfigurationModel(System.IO.File.ReadAllText(fileName));
                    return newFileData;
                }
                return null;
            });
            fileData = fileData ?? newFileData; // get new value if nothing was returned from GetOrAdd
            return fileData;
        }

        protected bool GetEnforcePostFromConfig(Guid? idpId)
        {
            bool enforcePost = false;

            if (idpId.HasValue)
            {
                var fileData = GetCachedConfiguration(idpId.Value);
                if (fileData != null)
                {
                    enforcePost = fileData.EnforcePOST;
                }
            }

            return enforcePost;
        }

        // Based on http://stackoverflow.com/a/17658754/401728
        protected ActionResult TestETag(string content, string responseETag, string contentType)
        {
            var requestedETag = Request.Headers["If-None-Match"];
            if (requestedETag == responseETag)
                return new HttpStatusCodeResult(HttpStatusCode.NotModified);

            Response.Cache.SetCacheability(HttpCacheability.ServerAndPrivate);
            Response.Cache.SetETag(responseETag);
            return Content(content, contentType);
        }
    }
}