using System;
using Microsoft.Owin;

namespace Sustainsys.Saml2.Owin.Extensions
{
    /// <summary>
    /// Extension helpers for <see cref="PathString"/>.
    /// </summary>
    public static class PathStringExtensions
    {
        // Based on the aspnet core implementation:
        // https://github.com/dotnet/aspnetcore/blob/c925f99cddac0df90ed0bc4a07ecda6b054a0b02/src/Http/Http.Abstractions/src/PathString.cs

        /// <summary>
        /// Determines whether the beginning of this <see cref="PathString"/> instance matches the specified <see cref="PathString"/> when compared
        /// using the specified comparison option and returns the remaining segments.
        /// </summary>
        /// <param name="value">The source <see cref="PathString"/>.</param>
        /// <param name="other">The <see cref="PathString"/> to compare.</param>
        /// <param name="comparisonType">One of the enumeration values that determines how this <see cref="PathString"/> and value are compared.</param>
        /// <param name="remaining">The remaining segments after the match.</param>
        /// <returns>true if value matches the beginning of this string; otherwise, false.</returns>
        public static bool StartsWithSegments(this PathString value, PathString other, StringComparison comparisonType, out PathString remaining)
        {
            var value1 = value.Value ?? string.Empty;
            var value2 = other.Value ?? string.Empty;
            if (value1.StartsWith(value2, comparisonType))
            {
                if (value1.Length == value2.Length || value1[value2.Length] == '/')
                {
                    remaining = new PathString(value1.Substring(value2.Length));
                    return true;
                }
            }
            remaining = PathString.Empty;
            return false;
        }
    }
}