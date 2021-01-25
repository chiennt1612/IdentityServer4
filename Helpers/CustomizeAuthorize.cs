using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServer.Helpers
{
    //[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
    public class CustomizeAuthorize : AuthorizeAttribute, IAuthorizationFilter //AuthorizeAttribute 
    {
        private readonly string _someFilterParameter;

        public CustomizeAuthorize(string someFilterParameter = "")
        {
            _someFilterParameter = someFilterParameter;
        }

        public void OnAuthorization(AuthorizationFilterContext context)
        {
            var user = context.HttpContext.User;

            if (!user.Identity.IsAuthenticated)
            {
                // it isn't needed to set unauthorized result 
                // as the base class already requires the user to be authenticated
                // this also makes redirect to a login page work properly
                // context.Result = new UnauthorizedResult();
                string path = context.HttpContext.Request.Path.ToString().Replace("?", "");
                string query = context.HttpContext.Request.QueryString.ToString().Replace("?", "");
                if (query != "") path = path + "?" + query;
                context.Result = new RedirectToRouteResult(
                        new RouteValueDictionary
                        {
                            { "action", "Login" },
                            { "controller", "Account" },
                            { "ReturnUrl", path }
                        });
                return;
            }

            //// you can also use registered services
            //var someService = context.HttpContext.RequestServices.GetService<ISomeService>();

            //var isAuthorized = someService.IsUserAuthorized(user.Identity.Name, _someFilterParameter);
            //if (!isAuthorized)
            //{
            //    context.Result = new StatusCodeResult((int)System.Net.HttpStatusCode.Forbidden);
            //    return;
            //}
        }
    }
}
