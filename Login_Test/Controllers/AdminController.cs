using Login_Test.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http.Headers;

namespace Login_Test.Controllers
{
    public class AdminController : Controller
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<JwtService> _logger;

        // Inject ILogger<JwtService> along with IConfiguration
        public AdminController(IConfiguration configuration, ILogger<JwtService> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }


        public async Task<IActionResult> AdminDashboard()
        {
            var jwt = Request.Cookies["AuthToken"];

            if (string.IsNullOrEmpty(jwt))
            {
                return Unauthorized("No token found");
            }

            using (var httpClient = new HttpClient())
            {
                httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);

                try
                {
                    var response = await httpClient.GetAsync("https://localhost:7035/AdminApi/GetData");
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
                catch (Exception ex)
                {
                    return Unauthorized($"Error during API call: {ex.Message}");
                }
            }
        }

    }


    [Route("AdminApi")]
    [Authorize(Roles ="User")]
    public class AdminApiController : ControllerBase
    {
        [HttpGet("GetData")]
        public List<int> GetData()
        {
            return new List<int> { 1, 2, 3 };
        }
    }

}
