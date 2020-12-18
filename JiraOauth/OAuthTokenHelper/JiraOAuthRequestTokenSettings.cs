using Atlassian.Jira.OAuth;

namespace JiraOauth.OAuthTokenHelper
{
    public class JiraOAuthRequestTokenSettings
    {
          /// <summary>
        /// The default relative URL to request a token.
        /// </summary>
        public const string DefaultRequestTokenUrl = "plugins/servlet/oauth/request-token";

        /// <summary>
        /// The default relative URL to authorize a token.
        /// </summary>
        public const string DefaultAuthorizeUrl = "plugins/servlet/oauth/authorize";

        /// <summary>
        /// Creates a Request token settings to generate a request token.
        /// </summary>
        /// <param name="url">The URL of the Jira instance to request to.</param>
        /// <param name="consumerKey">The consumer key provided by the Jira application link.</param>
        /// <param name="consumerSecret">The consumer private key in XML format.</param>
        /// <param name="callbackUrl">The callback url for the request token.</param>
        /// <param name="signatureMethod">The signature method used to sign the request.</param>
        /// <param name="requestTokenUrl">The relative URL to request the token.</param>
        /// <param name="authorizeUrl">The relative URL to authorize the token.</param>
        public JiraOAuthRequestTokenSettings(
            string url,
            string consumerKey,
            string consumerSecret,
            string callbackUrl = null,
            JiraOAuthSignatureMethod signatureMethod = JiraOAuthSignatureMethod.RsaSha1,
            string requestTokenUrl = DefaultRequestTokenUrl,
            string authorizeUrl = DefaultAuthorizeUrl)
        {
            Url = url;
            ConsumerKey = consumerKey;
            ConsumerSecret = consumerSecret;
            CallbackUrl = callbackUrl;
            SignatureMethod = signatureMethod;
            RequestTokenUrl = requestTokenUrl;
            AuthorizeUrl = authorizeUrl;
        }

        /// <summary>
        /// Gets the URL of the Jira instance to request to.
        /// </summary>
        public string Url { get; }

        /// <summary>
        /// Gets the consumer key provided by the Jira application link.
        /// </summary>
        public string ConsumerKey { get; }

        /// <summary>
        /// Gets the consumer private key in XML format.
        /// </summary>
        public string ConsumerSecret { get; }

        /// <summary>
        /// Gets the callback URL for the request token.
        /// </summary>
        public string CallbackUrl { get; }

        /// <summary>
        /// Gets the signature method used to sign the request.
        /// </summary>
        public JiraOAuthSignatureMethod SignatureMethod { get; }

        /// <summary>
        /// Gets the relative URL to request the token.
        /// </summary>
        public string RequestTokenUrl { get; }

        /// <summary>
        /// Gets the relative URL to authorize the token.
        /// </summary>
        public string AuthorizeUrl { get; }
    }
}