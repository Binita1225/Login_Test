using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Login_Test.Controllers
{
    public class UserController : Controller
    {
        //[Authorize]
        public IActionResult UserDashboard()
        {
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Login");
            }
            return View();
        }
    }
}
