using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Login_Test.Models
{
    public class Register
    {
        [Key]
        public int Id { get; set; } 
        [Required]
        public string FirstName { get; set; }
        [Required]
        public string LastName { get; set; }
        [Required]
        public string Address { get; set; }
        [Required]
        [EmailAddress(ErrorMessage = "Invalid email address")]
        public string Email { get; set; }
        [Required]
        [RegularExpression(@"^\d{10}$", ErrorMessage = "Phone number must be exactly 10 digits")]
        public int PhoneNumber { get; set; }

        
    }
}
