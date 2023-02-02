using System;
using System.Linq;
using System.Net;
using System.Web;
using System.Text;
using System.Net.Http;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;
using System.Security.Claims;
using System.Threading;
using System.Security.Principal;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Runtime.Caching;


namespace WebApplication3.Authorize
{
    public class BearerAuthorizationAttribute : AuthorizationFilterAttribute
    {
        private static readonly ObjectCache cache = MemoryCache.Default;


        public override void OnAuthorization(HttpActionContext actionContext)
        {
            var authHeader = actionContext.Request.Headers.Authorization;
            if (authHeader != null && authHeader.Scheme.Equals("Bearer", StringComparison.OrdinalIgnoreCase)
                 && !string.IsNullOrWhiteSpace(authHeader.Parameter))
            {
                var token = authHeader.Parameter;
             
                var principal = ValidateToken(token);
                if (principal == null)
                {
                    actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized);
                    return;
                }
                Thread.CurrentPrincipal = principal;
                HttpContext.Current.User = principal;
            }
            else
            {
                actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized);
                return;
            }
            base.OnAuthorization(actionContext);
        }

        private static IPrincipal ValidateToken(string token)
        {
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,            
                ValidateAudience = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("MbQeThWmZq4t7w!z")),
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };

            try
            {
                var claimsPrincipal = new JwtSecurityTokenHandler().ValidateToken(token, validationParameters, out var securityToken);

                if (securityToken is JwtSecurityToken jwtSecurityToken && jwtSecurityToken.ValidTo < DateTime.UtcNow)
                {
                    return null;
                }
                var jwt = securityToken as JwtSecurityToken;
                var id = new ClaimsIdentity(jwt.Claims, "jwt");
                return new ClaimsPrincipal(id);       
            }
            catch (SecurityTokenExpiredException)
            {
                return null;
            }
            catch (Exception)
            {
                return null;
            }

        }

    }
}