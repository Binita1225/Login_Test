using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Login_Test.Filters
{
    public class RoleValidationFilter : IActionFilter
    {
        private readonly string _requiredRole;

        public RoleValidationFilter(string requiredRole)
        {
            _requiredRole = requiredRole;
        }
        public void OnActionExecuted(ActionExecutedContext context)
        {
           
        }

        public void OnActionExecuting(ActionExecutingContext context)
        {
            var userRole = context.HttpContext.Session.GetString("Role");
            if (userRole != _requiredRole)
            {
                context.Result = new RedirectToActionResult("login", "Account", null);
            }
        }
    }
}
