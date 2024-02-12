using System.ComponentModel.DataAnnotations;

namespace CryptoApi.Models
{
    public class GenerateRsaSignatureRequest
    {
        [Required]
        public string PrivateKey { get; set; }

        [Required]
        public string Data { get; set; }
    }
}
