using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Login_Test.Models
{
    public class User
    {
        [Key]
        public int Id { get; set; }
        public string UserName { get; set; }
        [PasswordPropertyText]
        [DataType(DataType.Password)]
        public string Password { get; set; }
        public int UserId { get; set; }
        public byte[] Salt { get; set; }

        public string Role {  get; set; }
    }
}
