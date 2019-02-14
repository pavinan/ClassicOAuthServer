using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.OAuth;
using Owin;

namespace ClassicOAuthServer
{
    public partial class Startup
    {
        private readonly ConcurrentDictionary<string, string> _authenticationCodes =
            new ConcurrentDictionary<string, string>(StringComparer.Ordinal);



        public void ConfigurationAuth(IAppBuilder app)
        {
            app.UseCookieAuthentication(new CookieAuthenticationOptions()
            {
                AuthenticationType = Constants.CookieAuthType,
                ExpireTimeSpan = TimeSpan.FromDays(7),
                AuthenticationMode = AuthenticationMode.Active,
                LoginPath = new PathString("/Account/Login"),
                ReturnUrlParameter = "returnUrl"
            });

            app.UseOAuthAuthorizationServer(new OAuthAuthorizationServerOptions()
            {
                AllowInsecureHttp = true,
                AuthenticationMode = AuthenticationMode.Passive,
                AccessTokenExpireTimeSpan = TimeSpan.FromHours(1),
                AuthorizeEndpointPath = new PathString("/OAuth/Authorize"),
                TokenEndpointPath = new PathString("/OAuth/Token"),
                Provider = new OAuthAuthorizationServerProvider()
                {
                    OnValidateClientRedirectUri = ValidateClientRedirectUri,
                    OnValidateClientAuthentication = OnValidateClientAuthentication
                },
                AuthorizationCodeProvider = new AuthenticationTokenProvider()
                {
                    OnCreate = CreateAuthenticationCode,
                    OnReceive = ReceiveAuthenticationCode
                },
                RefreshTokenProvider = new AuthenticationTokenProvider()
                {
                    OnCreate = CreateRefreshToken,
                    OnReceive = ReceiveRefreshToken
                }
            });

        }




        private Task ValidateClientRedirectUri(OAuthValidateClientRedirectUriContext context)
        {
            // Step 1 for implicit or code

            // Check Redirect URI here call below method when valid
            context.Validated();
            return Task.CompletedTask;
        }

        private void CreateAuthenticationCode(AuthenticationTokenCreateContext context)
        {
            // Step 3 for code, this comes after authorize page

            context.SetToken(Guid.NewGuid().ToString());
            _authenticationCodes[context.Token] = context.SerializeTicket();
        }

        private void ReceiveAuthenticationCode(AuthenticationTokenReceiveContext context)
        {
            string value;
            if (_authenticationCodes.TryRemove(context.Token, out value))
            {
                context.DeserializeTicket(value);
            }
        }

        private Task OnValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            // this method is called for "/token"

            string clientId;
            string clientSecret;
            if (context.TryGetBasicCredentials(out clientId, out clientSecret) ||
                context.TryGetFormCredentials(out clientId, out clientSecret))
            {
                // check clientId and clientSecret here.

                context.Validated();
            }

            return Task.CompletedTask;
        }



        private void CreateRefreshToken(AuthenticationTokenCreateContext context)
        {
            // below line is not necessary but used for longer refresh tokens
            context.Ticket.Properties.ExpiresUtc = context.Ticket.Properties.ExpiresUtc?.AddDays(90);
            context.SetToken(context.SerializeTicket());
        }

        private void ReceiveRefreshToken(AuthenticationTokenReceiveContext context)
        {
            context.DeserializeTicket(context.Token);
        }
    }
}
