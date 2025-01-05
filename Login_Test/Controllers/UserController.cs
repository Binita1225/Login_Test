using Microsoft.AspNetCore.Mvc;

namespace Login_Test.Controllers
{
    public class UserController : Controller
    {
        public IActionResult UserDashboard()
        {
            return View();
        }
    }
}
