using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;

namespace ClassicOAuthServer.Controllers
{
    [Authorize]
    public class OAuthController : Controller
    {
        [HttpGet]
        public ActionResult Authorize()
        {
            // Step 2 for implicit            

            // if you don't want to ask "allow or deny" uncomment below line
            // OAuthSignIn();

            return View();
        }


        [HttpPost]
        public ActionResult Authorize(string button)
        {
            // Step 2 continution after allow for implicit

            if (button == "allow")
            {
                OAuthSignIn();
            }

            return View();
        }

        private void OAuthSignIn()
        {
            var identity = User.Identity as ClaimsIdentity;

            identity = new ClaimsIdentity(identity.Claims, "Bearer");
            HttpContext.GetOwinContext().Authentication.SignIn(identity);
        }

    }
}