using Microsoft.AspNetCore.Mvc;

namespace Login_Test.Controllers
{
    public class AccountController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
