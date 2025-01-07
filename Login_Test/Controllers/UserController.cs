using Login_Test.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System.Security.Claims;

namespace Login_Test.Controllers
{
    public class UserController : Controller
    {
        private readonly IConfiguration _configuration;

        public UserController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [Authorize(Roles ="User")]
        public IActionResult UserDashboard()
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

            var username = principal.Identity?.Name;
            var role = principal.FindFirst(ClaimTypes.Role)?.Value;

            ViewData["Username"] = username;
            ViewData["Role"] = role;

            return View();
        }
    }
}
