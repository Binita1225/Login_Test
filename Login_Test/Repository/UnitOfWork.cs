using Login_Test.Data;
using Login_Test.Repository.IRepository;

namespace Login_Test.Repository
{
    public class UnitOfWork : IUnitOfWork
    {
        private ApplicationDbContext _db;

        public IRegisterRepository Register { get; private set; }
        public IUserRepository User { get; private set; }

        public UnitOfWork(ApplicationDbContext db) 
        {
            _db = db;
            Register = new RegisterRepository(_db);
            User = new UserRepository(_db);
        }
        public void Save()
        {
            _db.SaveChanges();
        }
    }
}
