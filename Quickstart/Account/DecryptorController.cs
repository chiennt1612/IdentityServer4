using IdentityServer.Helpers;
using IdentityServer.Models;
using IdentityServer4.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServer.Controllers
{
    [CustomizeAuthorize]
    [SecurityHeaders]
    [Route("[controller]/[action]")]
    public class DecryptorController : Controller
    {
        public IActionResult Index()
        {
            DecryptorDTO model = new DecryptorDTO() { InputValue = "", OutputValue = "" };
            return View(model);
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Index(DecryptorDTO model, string button)
        {
            if (!ModelState.IsValid)
            {
                return View("Index", model);
            }

            if (String.IsNullOrEmpty(model.InputValue))
            {
                return View("Index", model);
            }
            var t = await Task.Run(() => {
                if(button == "Decrypt")
                {
                    if(model.Type == "Secret")
                    {
                        model.OutputValue = model.InputValue;
                    } else
                    {
                        model.OutputValue = DecryptorProvider.Decrypt(model.InputValue);
                    }
                }
                else
                {
                    if (model.Type == "Secret")
                    {
                        model.OutputValue = model.InputValue.Sha256();
                    }
                    else
                    {
                        model.OutputValue = DecryptorProvider.Encrypt(model.InputValue);
                    }                    
                }
                return model;
            });
            return View(t);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Decrypt(DecryptorDTO model)
        {
            if (!ModelState.IsValid)
            {
                return View("Index", model);
            }

            if (String.IsNullOrEmpty(model.InputValue))
            {
                return View("Index", model);
            }

            model.OutputValue = DecryptorProvider.Decrypt(model.InputValue);
            return View("Index", model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Encrypt(DecryptorDTO model)
        {
            if (!ModelState.IsValid)
            {
                return View("Index", model);
            }

            if (String.IsNullOrEmpty(model.InputValue))
            {
                return View("Index", model);
            }

            model.OutputValue = DecryptorProvider.Encrypt(model.InputValue);
            return View("Index", model);
        }
    }
}
