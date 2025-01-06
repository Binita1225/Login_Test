﻿using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Login_Test.Controllers
{
    public class AdminController : Controller
    {

        [Authorize(Roles ="Admin")]

        [HttpGet]
        public IActionResult AdminDashboard()
        {
            return View();
        }
    }
}
