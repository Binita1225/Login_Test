using Login_Test.Common;
using Login_Test.Data;
using Login_Test.Models;
using Login_Test.Models.ViewModels;
using Login_Test.Repository.IRepository;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.EntityFrameworkCore;
using System.Data.SqlTypes;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Login_Test.Controllers
{

    public class AccountController : Controller
    {
        private readonly ApplicationDbContext _db;

        // Constructor to initialize the database context
        public AccountController(ApplicationDbContext db)
        {
            _db = db;
        }

        //Default action to load the index page
        public IActionResult Index()
        {
            var username = HttpContext.Session.GetString("Username");

            return View();
        }

        // Action to display the registration form
        public IActionResult Register()
        {
            //added list of roles for dropdown
            var registerVM = new RegisterVM()
            {
                AvailableRoles = new List<string> { "User", "Admin" }
            };
            return View(registerVM);
        }

        [HttpPost]
        public IActionResult Register(RegisterVM model)
        {

            // Check if the provided model data is valid
            if (ModelState.IsValid)
            {
                // Start a database transaction for atomic operations
                using var transaction = (_db.Database.BeginTransaction());



                try
                {
                    //validate role selection
                    if (string.IsNullOrWhiteSpace(model.Role) || !new List<string> { "User", "Admin" }.Contains(model.Role))
                    {
                        ModelState.AddModelError("Role", "Invalid role");
                        //re-populate availableroles before returning to view
                        model.AvailableRoles = new List<string> { "User", "Admin" };
                        return View(model);
                    }

                    // Check if the username already exists in the database
                    var existingUser = _db.Users.FirstOrDefault(u => u.UserName == model.UserName);
                    if (existingUser != null)
                    {
                        ModelState.AddModelError("Username", "Username is already taken");
                        model.AvailableRoles = new List<string> { "User", "Admin" };
                        return View(model);
                    }

                    // Generate a salt and hash the provided password
                    string password = model.Password;

                    byte[] saltBytes = GenerateSalt();
                    // Hash the password with the salt
                    string hashedPassword = HashPassword(password, saltBytes);
                    string base64Salt = Convert.ToBase64String(saltBytes);

                    //string retrievedSaltBytes = base64Salt;
                    byte[] retrievedSaltBytes = Convert.FromBase64String(base64Salt);

                    // Save the registration details
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

                    // Save the user login details with hashed password and salt
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

                    // Commit the transaction if all operations succeed
                    transaction.Commit();

                    // Redirect to the login page after successful registration
                    return RedirectToAction("Login");
                }
                catch (Exception)
                {
                    // Rollback the transaction in case of an error
                    transaction.Rollback();
                    throw;
                }
            }

            model.AvailableRoles = new List<string> { "User", "Admin" };
            return View(model);
        }

        [AllowAnonymous]
        // Action to display the login form
        public IActionResult Login()
        {
            return View();
        }
        [AllowAnonymous]
        [HttpPost]
        public IActionResult Login(LoginVM model)
        {
            // Verify the user's credentials
            var verify = VeriryPassword(model);
    //        var usersdatalist = _db.Users.ToList();
            

            //var user = (from userDetail in _db.Users
            //            join register in _db.Registers
            //            on userDetail.UserId equals register.Id
            //            where userDetail.UserName == model.UserName
            //            select new LoginVM
            //            {
            //                UserName = userDetail.UserName,
            //                Password = model.Password,
            //                Address = register.Address
            //            }).FirstOrDefault();
            if (verify.Status) 
            {
                var searcheduser = _db.Users.FirstOrDefault(u => u.UserName == model.UserName);

                //var register = _db.Registers.FirstOrDefault(r => r.Id == searcheduser.UserId);
                //var verifyResult = VeriryPassword(model);

                if (searcheduser != null && verify.Status)
                {
                    var userRole = searcheduser.Role;

                    var register = _db.Registers.FirstOrDefault(r => r.Id == searcheduser.UserId);

                    // Store data in session ,Store the username in the session for later use with role
                    HttpContext.Session.SetString("Username", model.UserName);
                    HttpContext.Session.SetString("Role", userRole);




                    //CookieOptions options = new CookieOptions
                    //{
                    //    Expires = DateTimeOffset.UtcNow.AddSeconds(60),
                    //    Secure = true, // Ensures cookie is only sent over HTTPS
                    //    HttpOnly = true, // Not accessible via JavaScript
                    //};
                    //Response.Cookies.Append("UserTheme", theme, options);

                    //string? Username = Request.Cookies.ContainsKey(model.UserName) ?
                    //Request.Cookies[model.UserName] : null;

                    //string message = $"UserName: {UserName}";
                    //return message;

                    // Store the username in cookies 
                    //HttpContext.Response.Cookies.Append("Username", model.UserName);
                    //HttpContext.Response.Cookies.Append("Address", register.Address);
                    //HttpContext.Response.Cookies.Append("Message", S);

                    //create user claims
                    var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, searcheduser.UserName),
                        new Claim(ClaimTypes.Role, userRole)
                    };

                    //created identity & principal
                    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                    var principal = new ClaimsPrincipal(identity);

                    //sign in user with claims
                    HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

                    if (userRole == "Admin")
                    {
                        return RedirectToAction("AdminDashboard", "Admin");
                    }
                    else if (userRole == "User")
                    {
                        return RedirectToAction("UserDashboard", "User");
                    }

                    //return new ServiceResult<List<LoginVM>>()
                    //{
                    //    Data = "Success",
                    //    Message = "",
                    //    Status = ResultStatus.Success
                    //};

                    TempData["success"] = verify.Message;

                    // Redirect to the index page after successful login
                   // return RedirectToAction("Index");
                }
            }
            else
            {
                TempData["error"] = verify.Message;
            }

            //return RedirectToAction("Index");
            // Return a 404 error if login fails
            return View(model);
        }

       

        // Method to hash the password with a salt
        private string HashPassword(string password, byte[] salt)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] passwordBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));

                byte[] saltedPassword = new byte[password.Length + salt.Length];

                // Concatenate password and salt  
                Buffer.BlockCopy(passwordBytes, 0, saltedPassword, 0, password.Length);
                Buffer.BlockCopy(salt, 0, saltedPassword, password.Length, salt.Length);

                // Hash the concatenated password and salt
                byte[] hashedBytes = sha256.ComputeHash(saltedPassword);

                // Concatenate the salt and hashed password for storage
                byte[] hashedPasswordWithSalt = new byte[hashedBytes.Length + salt.Length];
                Buffer.BlockCopy(salt, 0, hashedPasswordWithSalt, 0, salt.Length);
                Buffer.BlockCopy(hashedBytes, 0, hashedPasswordWithSalt, salt.Length, hashedBytes.Length);

                return Convert.ToBase64String(hashedPasswordWithSalt);
            }
        }

        // Method to verify the entered password during login
        //private ServiceResult VeriryPassword(LoginVM model)
        //{
        //    //byte[] saltBytes = GenerateSalt();
        //    //var hashPassword = HashPassword(model.Password, saltBytes);

        //    // Retrieve the user from the database using the provided username
        //    // In a real scenario, you would retrieve these values from your database
        //    var user = _db.Users.Where(x => x.UserName == model.UserName).Select(x => x).FirstOrDefault();

        //    // Extract stored hash and salt
        //    string storedHashedPassword = user.Password;// "hashed_password_from_database";
        //    //string storedSalt = user.Salt; //"salt_from_database";
        //   //string storedSaltBytes = user.Salt;
        //    byte[] storedSaltBytes = user.Salt;
        //    string enteredPassword = model.Password; //"user_entered_password";

        //    // Convert the stored salt and entered password to byte arrays
        //    // byte[] storedSaltBytes = Convert.FromBase64String(user.Salt);
        //    byte[] enteredPasswordBytes = Encoding.UTF8.GetBytes(enteredPassword);

        //    // Concatenate entered password and stored salt
        //    byte[] saltedPassword = new byte[enteredPasswordBytes.Length + storedSaltBytes.Length];
        //    Buffer.BlockCopy(enteredPasswordBytes, 0, saltedPassword, 0, enteredPasswordBytes.Length);
        //    Buffer.BlockCopy(storedSaltBytes, 0, saltedPassword, enteredPasswordBytes.Length, storedSaltBytes.Length);

        //    // Hash the concatenated value
        //    string enteredPasswordHash = HashPassword(enteredPassword, storedSaltBytes);

        //    // Compare the entered password hash with the stored hash
        //    if (enteredPasswordHash == storedHashedPassword)
        //    {
        //        return new ServiceResult
        //        {
        //            Message = "Successfully login",
        //            Status = true

        //        };
        //    }
        //    else
        //    {
        //        return new ServiceResult
        //        {
        //            Message = "Verify your password",
        //            Status = false
        //        };
        //    }
        //}


        // Method to generate a cryptographically secure salt


        private ServiceResult VeriryPassword(LoginVM model)
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

            // Retrieve stored hashed password and salt from the database
            string storedHashedPassword = user.Password;
            byte[] storedSaltBytes = user.Salt;

            // Hash the entered password with the stored salt
            string enteredPasswordHash = HashPassword(model.Password, storedSaltBytes);

            // Compare the entered password hash with the stored hash
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

        static byte[] GenerateSalt()
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                byte[] salt = new byte[16]; // Adjust the size based on your security requirements
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

        public IActionResult AccessDenied()
        {
            return View();
        }

    }
}
