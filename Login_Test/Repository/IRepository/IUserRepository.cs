using Login_Test.Models;

namespace Login_Test.Repository.IRepository
{
    public interface IUserRepository : IRepository<User>
    {
        IEnumerable<User> GetAll();

        void Update(User obj);
    }
}
