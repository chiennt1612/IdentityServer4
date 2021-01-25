using IdentityServer.Helpers;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Threading.Tasks;

namespace IdentityServer.Services
{
    // This class is used by the application to send Email and SMS
    // when you turn on two-factor authentication in ASP.NET Identity.
    // For more details see this link https://go.microsoft.com/fwlink/?LinkID=532713
    public class SmsSender : ISmsSender
    {
        private readonly ILogger<SmsSender> _logger;
        public SmsSender(ILogger<SmsSender> logger)
        {
            _logger = logger;
        }
        public Task SendSmsAsync(string number, string message)
        {
            // Plug in your SMS service here to send a text message.

            // Please check MessageServices_twilio.cs or MessageServices_ASPSMS.cs
            // for implementation details.
            _logger.LogInformation($"Sending number: {number}, message: {message}");
            return Task.FromResult(0);
        }
    }
}
