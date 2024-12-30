using Login_Test.Models;

namespace Login_Test.Repository.IRepository
{
    public interface IRegisterRepository : IRepository<Register>
    {
        IEnumerable<Register> GetAll();

        void Update(Register obj);
    }
}
