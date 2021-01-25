using IdentityServer.Entities;
using Microsoft.EntityFrameworkCore;

namespace IdentityServer.Interfaces
{
    public interface ILogDbContext
    {
        DbSet<Log> Logs { get; set; }
    }
}
