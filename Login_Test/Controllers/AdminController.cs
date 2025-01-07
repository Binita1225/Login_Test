using Login_Test.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;

namespace Login_Test.Controllers
{
    public class AdminController : Controller
    {
        private readonly IConfiguration _configuration;

        public AdminController(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        //[AllowAnonymous]
        [Authorize(Roles = "Admin")]
        [HttpGet]
        public IActionResult AdminDashboard()
        {
            var token = Request.Cookies["AuthToken"];
            if (string.IsNullOrEmpty(token))
            {
                return Unauthorized("No token found");
            }

            var jwtService = new JwtService(_configuration);
            var principal = jwtService.ValidateToken(token);

            if (principal == null)
            {
                return Unauthorized("Invalid token");
            }

            ViewData["Username"] = principal.Identity?.Name;

            return View();
        }
    }
}
