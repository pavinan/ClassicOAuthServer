using ClassicOAuthServer.Models;
using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace ClassicOAuthServer.Controllers
{
    public class AccountController : Controller
    {
        [HttpGet]
        public ActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Login(LoginViewModel loginViewModel, string returnUrl)
        {
            // Check user name and password

            if (ModelState.IsValid)
            {
                var authentication = HttpContext.GetOwinContext().Authentication;

                var claims = new[]
                {
                    new Claim(ClaimTypes.Name, loginViewModel.Email)
                };

                var identity = new ClaimsIdentity(claims, Constants.CookieAuthType);

                var authProps = new AuthenticationProperties();

                authProps.IsPersistent = loginViewModel.RememberMe;

                authentication.SignIn(authProps, identity);
            }

            return View();
        }
    }
}