using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Web.Script.Serialization;

namespace LiveConnectOAuth.Modules
{
    public class LiveUser
    {
        // these are basic properties
        // extended properties are http://msdn.microsoft.com/en-us/library/hh243648.aspx#user
        public string id { get; set; }
        public string name { get; set; }
        public string first_name { get; set; }
        public string last_name { get; set; }
        public string gender { get; set; }
        // scope: wl.emails
        public LiveEmails emails { get; set; }
        public string locale { get; set; }

        // calculated value
        public DateTime expired { get; set; }

        public static LiveUser GetUser(LiveOAuthToken token)
        {
            var webRequest = (HttpWebRequest)WebRequest.Create("https://apis.live.net/v5.0/me?access_token=" + token.access_token);
            var webResponse = (HttpWebResponse)webRequest.GetResponse();

            var serializer = new JavaScriptSerializer();
            using (var stream = webResponse.GetResponseStream())
            {
                using (var reader = new StreamReader(stream))
                {
                    var user = serializer.Deserialize<LiveUser>(reader.ReadToEnd());
                    user.expired = token.expired;
                    return user;
                }
            }
        }

        public static LiveUser FromBytes(byte[] bytes)
        {
            var serializer = new JavaScriptSerializer();
            using (var stream = new MemoryStream(bytes))
            {
                using (var reader = new StreamReader(stream))
                {
                    return serializer.Deserialize<LiveUser>(reader.ReadToEnd());
                }
            }
        }

        public byte[] ToBytes()
        {
            var serializer = new JavaScriptSerializer();
            return Encoding.UTF8.GetBytes(serializer.Serialize(this));
        }

        public ClaimsPrincipal ToClaimsPrincipal()
        {
            var claims = new List<Claim>();
            AddClaim(claims, "id", id);
            AddClaim(claims, "name", name);
            AddClaim(claims, "first_name", first_name);
            AddClaim(claims, "last_name", last_name);
            AddClaim(claims, "gender", gender);
            AddClaim(claims, "locale", locale);
            AddClaim(claims, "email", emails.preferred);

            var identity = new ClaimsIdentity(new GenericIdentity(name, "live"), claims);
            var principal = new ClaimsPrincipal(identity);
            return principal;
        }

        public bool IsValid()
        {
            return DateTime.UtcNow < expired;
        }

        private static void AddClaim(List<Claim> claims, string type, string value)
        {
            if (!String.IsNullOrEmpty(value))
            {
                claims.Add(new Claim(type, value));
            }
        }

        public class LiveEmails
        {
            public string preferred { get; set; }
            public string account { get; set; }
            public string personal { get; set; }
            public string business { get; set; }
        }
    }
}