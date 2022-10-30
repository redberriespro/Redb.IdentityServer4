// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel;
using IdentityServer4.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using IdentityServer4.Configuration;
using Newtonsoft.Json;
using JsonElement = System.Text.Json.JsonElement;

namespace IdentityServer4.Extensions
{
    /// <summary>
    /// Extensions for Token
    /// </summary>
    public static class TokenExtensions
    {

        /// <summary>
        /// Creates the default JWT payload dictionary
        /// </summary>
        /// <param name="token"></param>
        /// <param name="options"></param>
        /// <param name="clock"></param>
        /// <param name="logger"></param>
        /// <returns></returns>
        public static JwtPayload CreateJwtPayload(this Token token,
            IdentityServerOptions options, ISystemClock clock, ILogger logger)
        {
            try
            {
                var payload = new JwtPayload
                {
                    { JwtClaimTypes.Issuer, token.Issuer }
                };

                // set times (nbf, exp, iat)
                var now = clock.UtcNow.ToUnixTimeSeconds();
                var exp = now + token.Lifetime;
                    
                payload.Add(JwtClaimTypes.NotBefore, now);
                payload.Add(JwtClaimTypes.IssuedAt, now);
                payload.Add(JwtClaimTypes.Expiration, exp);

                // add audience claim(s)
                if (token.Audiences.Any())
                {
                    if (token.Audiences.Count == 1)
                    {
                        payload.Add(JwtClaimTypes.Audience, token.Audiences.First());
                    }
                    else
                    {
                        payload.Add(JwtClaimTypes.Audience, token.Audiences);
                    }
                }

                // add confirmation claim (if present)
                if (token.Confirmation.IsPresent())
                {
                    payload.Add(JwtClaimTypes.Confirmation,
                        ParseConfirmation(token.Confirmation));
                }

                // scope claims
                var scopeClaims = token.Claims.Where(x => x.Type == JwtClaimTypes.Scope).ToArray();
                if (!scopeClaims.IsNullOrEmpty())
                {
                    var scopeValues = scopeClaims.Select(x => x.Value).ToArray();

                    if (options.EmitScopesAsSpaceDelimitedStringInJwt)
                    {
                        payload.Add(JwtClaimTypes.Scope, string.Join(" ", scopeValues));
                    }
                    else
                    {
                        payload.Add(JwtClaimTypes.Scope, scopeValues);
                    }
                }

                // amr claims
                var amrClaims = token.Claims.Where(x => x.Type == JwtClaimTypes.AuthenticationMethod).ToArray();
                if (!amrClaims.IsNullOrEmpty())
                {
                    var amrValues = amrClaims.Select(x => x.Value).Distinct().ToArray();
                    payload.Add(JwtClaimTypes.AuthenticationMethod, amrValues);
                }

                var simpleClaimTypes = token.Claims.Where(c =>
                        c.Type != JwtClaimTypes.AuthenticationMethod && c.Type != JwtClaimTypes.Scope)
                    .Select(c => c.Type)
                    .Distinct();

                // other claims
                foreach (var claimType in simpleClaimTypes)
                {
                    // we ignore claims that are added by the above code for token verification
                    if (!payload.ContainsKey(claimType))
                    {
                        var claims = token.Claims.Where(c => c.Type == claimType).ToArray();

                        if (claims.Count() > 1)
                        {
                            payload.Add(claimType, AddObjects(claims));
                        }
                        else
                        {
                            payload.Add(claimType, AddObject(claims.First()));
                        }
                    }
                }

                return payload;
            }
            catch (Exception ex)
            {
                logger.LogCritical(ex, "Error creating the JWT payload");
                throw;
            }
        }

        private static object ParseConfirmation(string confirmation)
        {
            return JsonConvert.DeserializeObject < Dictionary<string, object>>(confirmation);
        }

        private static IEnumerable<object> AddObjects(IEnumerable<Claim> claims)
        {
            foreach (var claim in claims)
            {
                yield return AddObject(claim);
            }
        }
            
        private static object AddObject(Claim claim)
        {
            if (claim.ValueType == ClaimValueTypes.Boolean)
            {
                return bool.Parse(claim.Value);
            }

            if (claim.ValueType == ClaimValueTypes.Integer || claim.ValueType == ClaimValueTypes.Integer32)
            {
                return int.Parse(claim.Value);
            }

            if (claim.ValueType == ClaimValueTypes.Integer64)
            {
                return long.Parse(claim.Value);
            }
            
            if (claim.ValueType == ClaimValueTypes.Double)
            {
                return double.Parse(claim.Value);
            }
            
            if (claim.ValueType == IdentityServerConstants.ClaimValueTypes.Json)
            {
                return System.Text.Json.JsonSerializer.Deserialize<JsonElement>(claim.Value);
            }

            return claim.Value;
        }
    }
}