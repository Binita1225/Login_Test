using Login_Test.Data;
using Login_Test.Models;
using Login_Test.Repository.IRepository;

namespace Login_Test.Repository
{
    public class RegisterRepository : Repository<Register>, IRegisterRepository
    {
        private ApplicationDbContext _db;
        public RegisterRepository   (ApplicationDbContext db) : base(db)
        {
            _db = db;
        }

        public IEnumerable<Register> GetAll()
        {
            return _db.Registers;
        }

        public void Update(Register obj)
        {
            _db.Registers.Update(obj);
        }

    }
}
