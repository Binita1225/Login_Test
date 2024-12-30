using Login_Test.Data;
using Login_Test.Repository.IRepository;

namespace Login_Test.Repository
{
    public class UnitOfWork : IUnitOfWork
    {
        private ApplicationDbContext _db;

        public UnitOfWork(ApplicationDbContext db) 
        {
            _db = db;
        }
        public void Save()
        {
            _db.SaveChanges();
        }
    }
}
