using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using Atlassian.Jira;
using Atlassian.Jira.OAuth;
using JiraOauth.OAuthTokenHelper;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace JiraOauth
{
    public class Startup
    {
        private static Dictionary<Guid, OAuthRequestToken> _requestTokenDb = new Dictionary<Guid, OAuthRequestToken>();
        private static Dictionary<Guid, string> _accessTokenDb = new Dictionary<Guid, string>();

        private string _url;
        private string _consumerKey;
        private string _consumerSecret;

        public Startup()
        {
            _url = "http://localhost:8001";
            _consumerKey = "OauthKey";

            var pemSecret = File.ReadAllText("jira_privatekey.pem");
            var privateKey = pemSecret;
            var decoder = new OpenSSL.PrivateKeyDecoder.OpenSSLPrivateKeyDecoder();
            var keyInfo = decoder.Decode(privateKey);
            _consumerSecret = OpenSSL.PrivateKeyDecoder.RSAExtensions.ToXmlString(keyInfo, true);
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseRouting();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapGet("/", async context =>
                {
                    var settings = new JiraOAuthRequestTokenSettings(_url, _consumerKey, _consumerSecret,
                        "http://localhost:1234/callback");

                    var requestToken = await JiraOAuthTokenHelper.GenerateRequestTokenAsync(settings);
                    var requestTokenId = Guid.NewGuid();

                    _requestTokenDb.Add(requestTokenId, requestToken);

                    context.Response.Cookies.Append("JiraRequestTokenCookie", requestTokenId.ToString());
                    context.Response.Redirect(requestToken.AuthorizeUri);
                });

                endpoints.MapGet("/callback", async context =>
                {
                    var exists =
                        context.Request.Cookies.TryGetValue("JiraRequestTokenCookie", out var stringRequestTokenId);
                    if (!exists || !Guid.TryParse(stringRequestTokenId, out var requestTokenId) ||
                        !_requestTokenDb.ContainsKey(requestTokenId))
                    {
                        context.Response.Cookies.Delete("JiraRequestTokenCookie");
                        context.Response.Cookies.Delete("JiraAccessTokenCookie");
                        context.Response.Redirect("/");
                        return;
                    }

                    var requestToken = _requestTokenDb[requestTokenId];
                    var verifier = context.Request.Query["oauth_verifier"].ToString();

                    var settings = new JiraOAuthAccessTokenSettings(_url, _consumerKey, _consumerSecret, requestToken.OAuthToken, requestToken.OAuthTokenSecret, verifier);
                    var accessToken = await JiraOAuthTokenHelper.ObtainAccessTokenAsync(settings, CancellationToken.None);

                    if (accessToken == null)
                    {
                        context.Response.Cookies.Delete("JiraRequestTokenCookie");
                        context.Response.Redirect("/");
                        return;
                    }

                    var accessTokenId = Guid.NewGuid();
                    _accessTokenDb.Add(accessTokenId, accessToken);

                    context.Response.Cookies.Append("JiraAccessTokenCookie", accessTokenId.ToString());
                    context.Response.Redirect("/result");
                });

                endpoints.MapGet("/result", async context =>
                {
                    var requestTokenExists = context.Request.Cookies.TryGetValue("JiraRequestTokenCookie", out var stringRequestTokenId);
                    var accessTokenExists = context.Request.Cookies.TryGetValue("JiraAccessTokenCookie", out var stringAccessTokenId);
                    if (!requestTokenExists || !accessTokenExists || 
                        !Guid.TryParse(stringRequestTokenId, out var requestTokenId) || !_requestTokenDb.ContainsKey(requestTokenId) ||
                        !Guid.TryParse(stringAccessTokenId, out var accessTokenId) || !_accessTokenDb.ContainsKey(accessTokenId))
                    {
                        context.Response.Cookies.Delete("JiraRequestTokenCookie");
                        context.Response.Cookies.Delete("JiraAccessTokenCookie");
                        context.Response.Redirect("/");
                        return;
                    }

                    var requestToken = _requestTokenDb[requestTokenId];
                    var accessToken = _accessTokenDb[accessTokenId];

                    var jira = Jira.CreateOAuthRestClient(_url, _consumerKey, _consumerSecret, accessToken, requestToken.OAuthTokenSecret);

                    var result = await jira.Issues.GetIssuesFromJqlAsync("project = JSS");
                    var issue = result.First();
                    var vm = new
                    {
                        Created = issue.Created, Description = issue.Description, Title = issue.Summary,
                        Reporter = issue.Reporter, Type = issue.Type.Name, Priority = issue.Priority.Name
                    };
                    await context.Response.WriteAsJsonAsync(vm);
                });
            });
        }
    }
}