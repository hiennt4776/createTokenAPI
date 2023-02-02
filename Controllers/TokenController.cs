using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using System.Security.Claims;
using System.Threading;
using System.Security.Principal;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Text.Json;
using WebApplication3.Models;
using System.Web;
using System.Runtime.Caching;

namespace WebApplication3.Controllers
{
    public class TokenController : ApiController
    {

        private static readonly ObjectCache cache = MemoryCache.Default;

        [HttpPost]
   
        public IHttpActionResult GenerateToken(Credentials credentials)
        {
            if (credentials.client_id == "bOZdxAfCvWZkYdD82sfcp56cOL0a"
                && credentials.client_secret == "d5C3PmbGfiyS2dIShOafxxonFIAa"
                && credentials.grant_type == "client_credentials")
                {
                TokenCreate tokenCreate = new TokenCreate();
                string serializedTokenCreate = (string)cache["tokenCreate"];

                if (serializedTokenCreate != null)
                {
                    tokenCreate = JsonSerializer.Deserialize<TokenCreate>(serializedTokenCreate);
                    if (countDownExpired(tokenCreate) < 0)
                    {
                        tokenCreate = GenerateAccessToken();
                        cache["tokenCreate"] = JsonSerializer.Serialize(tokenCreate);

                    }
                }
                else {
                    tokenCreate = GenerateAccessToken();
                    cache["tokenCreate"] = JsonSerializer.Serialize(tokenCreate);
                }
        
                TokenOutput tokenOutput = new TokenOutput();
                tokenOutput.bearerString = tokenCreate.bearerString;
                var sec = countDownExpired(tokenCreate);
                tokenOutput.secondLength = Convert.ToInt32(countDownExpired(tokenCreate));
                return Ok(new { tokenOutput });
                }
                else
                {
                    return Unauthorized();
                }
        }

        private double countDownExpired(TokenCreate tokenCreate)
        {
            var deltaSecond = (DateTime.Now - tokenCreate.createDate).TotalSeconds;
            return tokenCreate.secondLength - deltaSecond;
        }

        private TokenCreate GenerateAccessToken()
        {
            var h = new JwtSecurityTokenHandler();
            var now = DateTime.Now;
            var token = h.CreateToken(new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim("client_id", "bOZdxAfCvWZkYdD82sfcp56cOL0a"),
                    new Claim("client_secret", "d5C3PmbGfiyS2dIShOafxxonFIAa"),
                    new Claim("grant_type", "client_credentials")
                }),
                Expires = now.AddMinutes(15),
                //Subject = id,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes("MbQeThWmZq4t7w!z")), SecurityAlgorithms.HmacSha256)
            });
            TokenCreate tokenCreate = new TokenCreate();
            tokenCreate.createDate = DateTime.Now;
            tokenCreate.bearerString = h.WriteToken(token);
            tokenCreate.secondLength = 900;

            return tokenCreate;

        }


    }
     public class TokenOutput
    {
        public string bearerString { get; set; }
        //public DateTime createDate { get; set; }
        public int secondLength { get; set; }
    }
    public class Credentials
    {
        public string client_id { get; set; }
        public string client_secret { get; set; }
        public string grant_type { get; set; }
    }
    
}
