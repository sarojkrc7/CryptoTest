using System.ComponentModel.DataAnnotations;

namespace CryptoApi.Models
{
    public class DecryptRsaNoneOaepSha256Mgf1PaddingRequest
    {
        [Required]
        public string PrivateKey { get; set; }

        [Required]
        public string CipheredData { get; set; }
    }
}
