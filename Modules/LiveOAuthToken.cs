using System;
using System.IO;
using System.Web.Script.Serialization;

namespace LiveConnectOAuth.Modules
{
    public class LiveOAuthToken
    {
        public string token_type { get; set; }
        public int expires_in { get; set; }
        public string scope { get; set; }
        public string access_token { get; set; }
        public string user_id { get; set; }
        public DateTime expired { get; set; }

        public static LiveOAuthToken FromStream(Stream stream)
        {
            var serializer = new JavaScriptSerializer();
            using (var reader = new StreamReader(stream))
            {
                var token = serializer.Deserialize<LiveOAuthToken>(reader.ReadToEnd());
                token.expired = DateTime.UtcNow.AddSeconds(token.expires_in);
                return token;
            }
        }
    }
}