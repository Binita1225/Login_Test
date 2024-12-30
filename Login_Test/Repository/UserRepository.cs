using Login_Test.Data;
using Login_Test.Models;
using Login_Test.Repository.IRepository;

namespace Login_Test.Repository
{
    public class UserRepository : Repository<User>, IUserRepository
    {
        private ApplicationDbContext _db;
        public UserRepository(ApplicationDbContext db) : base(db)
        {
            _db = db;
        }

        public IEnumerable<User> GetAll()
        {
            return _db.Users;
        }

        public void Update(User obj)
        {
            _db.Users.Update(obj);
        }
    }
}
