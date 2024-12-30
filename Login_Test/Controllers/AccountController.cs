using Login_Test.Repository.IRepository;
using Microsoft.AspNetCore.Mvc;

namespace Login_Test.Controllers
{
    public class AccountController : Controller
    {
        private readonly IUnitOfWork _unitOfWork;

        public AccountController(IUnitOfWork unitOfWork)
        {
            _unitOfWork = unitOfWork; 
        }
        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Register()
        {
            return View();
        }
        
        public IActionResult Login()
        {
            return View();
        }
    }
}
