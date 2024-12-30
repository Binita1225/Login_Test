using Login_Test.Models;
using Microsoft.EntityFrameworkCore;

namespace Login_Test.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {

        }

        public DbSet<Register> Registers { get; set; }
        public DbSet<User> Users { get; set; }        

    }
}
