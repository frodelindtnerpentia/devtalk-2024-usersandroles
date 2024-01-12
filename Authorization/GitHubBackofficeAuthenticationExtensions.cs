using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;

namespace UsersAndGroups.Authorization
{
    public static class GitHubBackofficeAuthenticationExtensions
    {
        public static IUmbracoBuilder AddGitHubBackofficeAuthentication(this IUmbracoBuilder builder)
        {
            // Register GitHubBackOfficeExternalLoginProviderOptions here rather than require it in startup
            builder.Services.ConfigureOptions<GitHubBackOfficeExternalLoginProviderOptions>();
            builder.AddBackOfficeExternalLogins(logins =>
            {
                logins.AddBackOfficeLogin(
                    backOfficeAuthenticationBuilder =>
                    {
#pragma warning disable CS8604 // Possible null reference argument.
                        backOfficeAuthenticationBuilder.AddGitHub(
                            backOfficeAuthenticationBuilder.SchemeForBackOffice(GitHubBackOfficeExternalLoginProviderOptions.SchemeName),
                                options =>
                                {
                                    options.Scope.Add("user:email");
                                    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                                    options.ClientId = "";
                                    options.ClientSecret = "";
                                    options.CallbackPath = "/signin-provider";

                                    options.Events.OnTicketReceived = ctx =>
                                    {
                                        var username = ctx.Principal.FindFirstValue(ClaimTypes.Email)
                                                ?? ctx.Principal.FindFirstValue("email")
                                                ?? throw new Exception("Missing email claim");
                                        if (username != null && ctx.Principal?.Identity is ClaimsIdentity claimsIdentity)
                                        {
                                            claimsIdentity.AddClaim(
                                                new Claim(
                                                    ClaimTypes.Email,
                                                    username
                                                )
                                            );
                                        }
                                        return Task.CompletedTask;
                                    };
                                });
#pragma warning restore CS8604 // Possible null reference argument.
                    });
            });
            return builder;
        }
    }
}