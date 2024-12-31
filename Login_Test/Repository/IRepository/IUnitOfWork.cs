namespace Login_Test.Repository.IRepository
{
    public interface IUnitOfWork
    {
        IRegisterRepository Register {  get; }
        IUserRepository User { get; }
        void Save();
    }
}
