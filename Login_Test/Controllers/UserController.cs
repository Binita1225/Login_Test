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
        private readonly ILogger<JwtService> _logger;

        public UserController(IConfiguration configuration, ILogger<JwtService> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

     
        public async Task<IActionResult> UserDashboard()
        {

            var jwt = Request.Cookies["AuthToken"];

            if (string.IsNullOrEmpty(jwt))
            {
                return Unauthorized("Token not found");
            }

            using (var httpClient = new HttpClient()) {

                httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);

                try
                {
                    var response = await httpClient.GetAsync("https://localhost:7035/UserApi/GetData");
                    if (response.IsSuccessStatusCode)
                    {
                        var data = await response.Content.ReadAsStringAsync();

                        return View();
                    }
                    else
                    {
                        return RedirectToAction("Login", "Account");
                    }
                }
                catch (Exception ex) {

                    return Unauthorized($"Error: {ex.Message}");
                }

            }

        }
    }


    [Route("UserApi")]
    [Authorize(Roles = "User")]
    public class UserApiController : ControllerBase
    {
        [HttpGet("GetData")]
        public List<int> GetData()
        {
            return new List<int> { 1, 2, 3 };
        }
    }
}
