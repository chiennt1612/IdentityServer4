using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServer.Constants
{
    public class TableConsts
    {
        public const string Logging = "Logs";
        public const string AuditLog = "AuditLogs";
        public const string IdentityRoles = "Roles";
        public const string IdentityRoleClaims = "RoleClaims";
        public const string IdentityUserRoles = "UserRoles";
        public const string IdentityUsers = "Users";
        public const string IdentityUserLogins = "UserLogins";
        public const string IdentityUserClaims = "UserClaims";
        public const string IdentityUserTokens = "UserTokens";
    }

    public class AuthorizationConsts
    {
        public const string AdministrationPolicy = "AdministratorRole";
    }

}
