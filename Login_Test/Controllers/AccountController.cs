using Login_Test.Data;
using Login_Test.Models;
using Login_Test.Models.ViewModels;
using Login_Test.Repository.IRepository;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Data.SqlTypes;
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
            return View();
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
                    // Check if the username already exists in the database
                    var existingUser = _db.Users.FirstOrDefault(u => u.UserName == model.UserName);
                    if (existingUser != null)
                    {
                        ModelState.AddModelError("Username", "Username is already taken");
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
                        Salt = retrievedSaltBytes
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
            return View();     
        }

        // Action to display the login form
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public IActionResult Login(LoginVM model)
        {
            // Verify the user's credentials
            var verify = VeriryPassword(model);
            //var user 
            if (verify) 
            {
                // Store data in session ,Store the username in the session for later use
                HttpContext.Session.SetString("Username", model.UserName);

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
                HttpContext.Response.Cookies.Append("Username", model.UserName);
                // HttpContext.Response.Cookies.Append("Address", model.Address);

                // Redirect to the index page after successful login
                return RedirectToAction("Index");
            }

            //return RedirectToAction("Index");
            // Return a 404 error if login fails
            return NotFound();
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
        private bool VeriryPassword(LoginVM model)
        {
            //byte[] saltBytes = GenerateSalt();
            //var hashPassword = HashPassword(model.Password, saltBytes);

            // Retrieve the user from the database using the provided username
            // In a real scenario, you would retrieve these values from your database
            var user = _db.Users.Where(x => x.UserName == model.UserName).Select(x => x).FirstOrDefault();
           
            // Extract stored hash and salt
            string storedHashedPassword = user.Password;// "hashed_password_from_database";
            //string storedSalt = user.Salt; //"salt_from_database";
           //string storedSaltBytes = user.Salt;
            byte[] storedSaltBytes = user.Salt;
            string enteredPassword = model.Password; //"user_entered_password";

            // Convert the stored salt and entered password to byte arrays
            // byte[] storedSaltBytes = Convert.FromBase64String(user.Salt);
            byte[] enteredPasswordBytes = Encoding.UTF8.GetBytes(enteredPassword);

            // Concatenate entered password and stored salt
            byte[] saltedPassword = new byte[enteredPasswordBytes.Length + storedSaltBytes.Length];
            Buffer.BlockCopy(enteredPasswordBytes, 0, saltedPassword, 0, enteredPasswordBytes.Length);
            Buffer.BlockCopy(storedSaltBytes, 0, saltedPassword, enteredPasswordBytes.Length, storedSaltBytes.Length);

            // Hash the concatenated value
            string enteredPasswordHash = HashPassword(enteredPassword, storedSaltBytes);

            // Compare the entered password hash with the stored hash
            if (enteredPasswordHash == storedHashedPassword)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        // Method to generate a cryptographically secure salt
        static byte[] GenerateSalt()
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                byte[] salt = new byte[16]; // Adjust the size based on your security requirements
                rng.GetBytes(salt);
                return salt;
            }
        }

    }
}
