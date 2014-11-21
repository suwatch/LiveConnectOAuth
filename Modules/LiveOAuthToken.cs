using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Claims;
using System.Text;
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

        // calculated
        public IDictionary<string, object> claims { get; set; }

        public static LiveOAuthToken FromStream(Stream stream)
        {
            var serializer = new JavaScriptSerializer();
            using (var reader = new StreamReader(stream))
            {
                var token = serializer.Deserialize<LiveOAuthToken>(reader.ReadToEnd());
                token.Initialize();
                return token;
            }
        }

        private void Initialize()
        {
            var webRequest = (HttpWebRequest)WebRequest.Create("https://apis.live.net/v5.0/me?access_token=" + access_token);
            var webResponse = (HttpWebResponse)webRequest.GetResponse();

            var serializer = new JavaScriptSerializer();
            using (var stream = webResponse.GetResponseStream())
            {
                using (var reader = new StreamReader(stream))
                {
                    claims = serializer.Deserialize<Dictionary<string, object>>(reader.ReadToEnd());
                    claims["session_start"] = DateTime.UtcNow;
                    claims["session_end"] = DateTime.UtcNow.AddSeconds(expires_in);
                }
            }
        }

        public bool IsValid()
        {
            return DateTime.UtcNow < (DateTime)claims["session_end"];
        }

        public static LiveOAuthToken FromBytes(byte[] bytes)
        {
            var serializer = new JavaScriptSerializer();
            using (var stream = new MemoryStream(bytes))
            {
                using (var reader = new StreamReader(stream))
                {
                    return serializer.Deserialize<LiveOAuthToken>(reader.ReadToEnd());
                }
            }
        }

        public byte[] ToBytes()
        {
            var serializer = new JavaScriptSerializer();
            return Encoding.UTF8.GetBytes(serializer.Serialize(this));
        }

        public ClaimsPrincipal GetPrincipal()
        {
            var list = new List<Claim>();
            foreach (var pair in claims)
            {
                AddClaim(list, pair.Key, pair.Value);
            }

            var identity = new ClaimsIdentity(list, "live");
            return new ClaimsPrincipal(identity);
        }

        static void AddClaim(List<Claim> claims, string key, object value)
        {
            if (value == null)
            {
                //claims.Add(new Claim(key, "<null>"));
            }
            else if (value is ArrayList)
            {
                var array = (ArrayList)value;
                for (int i = 0; i < array.Count; ++i)
                {
                    AddClaim(claims, String.Format("{0}[{1}]", key, i), array[i]);
                }
            }
            else if (value is Dictionary<string, object>)
            {
                var dict = (Dictionary<string, object>)value;
                foreach (var item in dict)
                {
                    AddClaim(claims, String.Format("{0}.{1}", key, item.Key), item.Value);
                }
            }
            else
            {
                claims.Add(new Claim(key, value.ToString(), value.GetType().Name));
            }
        }
    }
}