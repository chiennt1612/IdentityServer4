using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServer.Models
{
    public class DecryptorDTO
    {
        [Required]
        public string InputValue { get; set; }
        public string OutputValue { get; set; }
        public string Type { get; set; }
    }
}
