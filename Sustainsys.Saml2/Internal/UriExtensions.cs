using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Sustainsys.Saml2.Internal
{
    static class UriExtensions
    {
        public static bool IsHttps(this Uri uri)
        {
            return string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase);
        }

        public static string ExtractIdFromLocalUri(string uri) {
            string idref = uri.Substring(1);

            // Deal with XPointer of type #xpointer(id("ID")). Other XPointer support isn't handled here and is anyway optional 
            if (idref.StartsWith("xpointer(id(", StringComparison.Ordinal)) {
                int startId = idref.IndexOf("id(", StringComparison.Ordinal);
                int endId = idref.IndexOf(")", StringComparison.Ordinal);
                if (endId < 0 || endId < startId + 3) {
                    throw new CryptographicException("Invalid XML Cryptography Reference");
                }                
                idref = idref.Substring(startId + 3, endId - startId - 3);
                idref = idref.Replace("\'", "");
                idref = idref.Replace("\"", "");
            }
            return idref;
        }
    }
}
