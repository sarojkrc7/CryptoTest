using System.ComponentModel.DataAnnotations;

namespace CryptoApi.Models
{
    public class EncryptRsaNoneOaepSha256Mgf1PaddingRequest
    {
        [Required]
        public string PublicKey { get; set; }

        [Required]
        public string Data { get; set; }
    }
}
