using Microsoft.AspNetCore.Identity;
using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace IdentityServer.Models
{
    // Add profile data for application users by adding properties to the ApplicationUser class
    public class ApplicationUser : IdentityUser<long>
    {
        //[DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        ////[MaxLength(36)]
        //public virtual long Id { get; set; }
        [MaxLength(200)]
        public string Fullname { get; set; }
        [MaxLength(36)]
        public string OldId { get; set; }
        public ApplicationUser()
        {
            OldId = Guid.NewGuid().ToString();
        }
    }

    public class ApplicationRole : IdentityRole<long>
    {
        //[DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        ////[MaxLength(36)]
        //public virtual long Id { get; set; }
    }

    public class ApplicationUserClaim : IdentityUserClaim<long>
    {
    }

    public class ApplicationUserRole : IdentityUserRole<long>
    {

    }

    public class ApplicationUserLogin : IdentityUserLogin<long>
    {

    }

    public class ApplicationUserRoleClaim : IdentityRoleClaim<long>
    {

    }

    public class ApplicationUserToken : IdentityUserToken<long>
    {

    }
}
