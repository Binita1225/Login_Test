using Login_Test.Data;
using Login_Test.Models;
using Login_Test.Models.ViewModels;
using Login_Test.Repository.IRepository;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;

namespace Login_Test.Controllers
{
    public class AccountController : Controller
    {
        private readonly ApplicationDbContext _db;

        public AccountController(ApplicationDbContext db)
        {
            _db = db; 
        }
       

            public IActionResult Index()
        {
            return View();
        }

        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public IActionResult Register(RegisterVM model) 
        {
            var registration = new Register()
            {
                FirstName = model.FirstName,
                LastName = model.LastName,
                Address = model.Address,
                Email = model.Email,
              
                PhoneNumber = model.PhoneNumber
            };

           var result = _db.Registers.Add(registration);
            _db.SaveChanges();
            var loginUser = new User()
            {
                UserName = model.UserName,
                Password = model.Password,
                UserId = registration.Id
            };
            if (true)
            {

            }

            _db.Users.Add(loginUser);
            _db.SaveChanges();
            

            return RedirectToAction("Login");
        }
        
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public IActionResult Login(RegisterVM model)
        {
            var user = _db.Users.FirstOrDefault(u => u.UserName == model.UserName && u.Password == model.Password);
            if (user != null)
            {
               return RedirectToAction("Index");
            }

            //return RedirectToAction("Index");
            return NotFound();
        }

        private string HashPassword(string password)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                return Convert.ToBase64String(bytes);
            }
        }
    }
}
