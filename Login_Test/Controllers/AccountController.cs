using Login_Test.Data;
using Login_Test.Models;
using Login_Test.Models.ViewModels;
using Login_Test.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Login_Test.Common;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;

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
            var username = HttpContext.Session.GetString("Username");
            return View();
        }

        public IActionResult Register()
        {
            var registerVM = new RegisterVM()
            {
                AvailableRoles = new List<string> { "User", "Admin" }
            };
            return View(registerVM);
        }

        [HttpPost]
        public IActionResult Register(RegisterVM model)
        {
            if (ModelState.IsValid)
            {
                using var transaction = (_db.Database.BeginTransaction());
                try
                {
                    if (string.IsNullOrWhiteSpace(model.Role) || !new List<string> { "User", "Admin" }.Contains(model.Role))
                    {
                        ModelState.AddModelError("Role", "Invalid role");
                        model.AvailableRoles = new List<string> { "User", "Admin" };
                        return View(model);
                    }

                    var existingUser = _db.Users.FirstOrDefault(u => u.UserName == model.UserName);
                    if (existingUser != null)
                    {
                        ModelState.AddModelError("Username", "Username is already taken");
                        model.AvailableRoles = new List<string> { "User", "Admin" };
                        return View(model);
                    }

                    string password = model.Password;
                    byte[] saltBytes = GenerateSalt();
                    string hashedPassword = HashPassword(password, saltBytes);
                    string base64Salt = Convert.ToBase64String(saltBytes);
                    byte[] retrievedSaltBytes = Convert.FromBase64String(base64Salt);

                    var registration = new Register()
                    {
                        FirstName = model.FirstName,
                        LastName = model.LastName,
                        Address = model.Address,
                        Email = model.Email,
                        PhoneNumber = model.PhoneNumber
                    };
                    _db.Registers.Add(registration);
                    _db.SaveChanges();

                    var loginUser = new User()
                    {
                        UserName = model.UserName,
                        Password = hashedPassword,
                        UserId = registration.Id,
                        Salt = retrievedSaltBytes,
                        Role = model.Role
                    };

                    _db.Users.Add(loginUser);
                    _db.SaveChanges();

                    transaction.Commit();
                    return RedirectToAction("Login");
                }
                catch (Exception)
                {
                    transaction.Rollback();
                    throw;
                }
            }

            model.AvailableRoles = new List<string> { "User", "Admin" };
            return View(model);
        }

        [AllowAnonymous]
        public IActionResult Login()
        {
            return View();
        }

        [AllowAnonymous]
        [HttpPost]
        public IActionResult Login(LoginVM model, [FromServices] IJwtService jwtService)
        {
            var verify = VerifyPassword(model);
            if (!verify.Status)
            {
                TempData["error"] = verify.Message;
                return View(model);
            }

            var searchedUser = _db.Users.FirstOrDefault(u => u.UserName == model.UserName);
            if (searchedUser == null)
            {
                TempData["error"] = "User not found.";
                return View(model);
            }

            var userRole = searchedUser.Role;
            var token = jwtService.GenerateToken(searchedUser.UserName, userRole);
            HttpContext.Response.Cookies.Append("AuthToken", token, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                Expires = DateTime.UtcNow.AddHours(1)
            });

            TempData["success"] = "Login successful.";
            return userRole switch
            {
                "Admin" => RedirectToAction("AdminDashboard", "Admin"),
                "User" => RedirectToAction("UserDashboard", "User"),
                _ => View(model)
            };
        }

        private ServiceResult VerifyPassword(LoginVM model)
        {
            var user = _db.Users.Where(x => x.UserName == model.UserName).FirstOrDefault();

            if (user == null)
            {
                return new ServiceResult
                {
                    Message = "User not found",
                    Status = false
                };
            }

            string storedHashedPassword = user.Password;
            byte[] storedSaltBytes = user.Salt;

            string enteredPasswordHash = HashPassword(model.Password, storedSaltBytes);

            if (enteredPasswordHash == storedHashedPassword)
            {
                return new ServiceResult
                {
                    Message = "Successfully logged in",
                    Status = true
                };
            }
            else
            {
                return new ServiceResult
                {
                    Message = "Verify your password",
                    Status = false
                };
            }
        }

        private string HashPassword(string password, byte[] salt)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] passwordBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                byte[] saltedPassword = new byte[password.Length + salt.Length];
                Buffer.BlockCopy(passwordBytes, 0, saltedPassword, 0, password.Length);
                Buffer.BlockCopy(salt, 0, saltedPassword, password.Length, salt.Length);
                byte[] hashedBytes = sha256.ComputeHash(saltedPassword);

                byte[] hashedPasswordWithSalt = new byte[hashedBytes.Length + salt.Length];
                Buffer.BlockCopy(salt, 0, hashedPasswordWithSalt, 0, salt.Length);
                Buffer.BlockCopy(hashedBytes, 0, hashedPasswordWithSalt, salt.Length, hashedBytes.Length);

                return Convert.ToBase64String(hashedPasswordWithSalt);
            }
        }

        static byte[] GenerateSalt()
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                byte[] salt = new byte[16];
                rng.GetBytes(salt);
                return salt;
            }
        }

        public IActionResult Logout()
        {
            if (User.Identity.IsAuthenticated)
            {
                HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme).Wait();
            }
            return RedirectToAction("Index");
        }
    }
}
