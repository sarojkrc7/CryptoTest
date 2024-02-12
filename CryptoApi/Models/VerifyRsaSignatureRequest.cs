using System.ComponentModel.DataAnnotations;

namespace CryptoApi.Models
{
    public class VerifyRsaSignatureRequest
    {
        [Required]
        public string PublicKey { get; set; }

        [Required]
        public string Base64Signature { get; set; }

        [Required]
        public string SignatureData { get; set; }
    }
}
