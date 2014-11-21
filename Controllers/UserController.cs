using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web;
using System.Web.Http;

namespace LiveConnectOAuth.Controllers
{
    public class UserController : ApiController
    {
        // GET api/user
        [Authorize]
        public IDictionary<string, string> Get()
        {
            var dictionary = new Dictionary<string, string>();
            foreach (var claim in ((ClaimsPrincipal)HttpContext.Current.User).Claims)
            {
                dictionary[claim.Type] = claim.Value;
            }

            return dictionary;
        }
    }
}
