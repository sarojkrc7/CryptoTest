using Core;
using CryptoApi.Dtos;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Asn1.Ocsp;
using System.Text;

namespace CryptoApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class MypayCryptoController : ControllerBase
    {
        [HttpGet("encrypt-string")]
        public async Task<IActionResult> EncryptString(string plainText)
        {
            try
            {

                if (string.IsNullOrWhiteSpace(plainText))
                    return BadRequest(new { Message = "Input string can not be empty" });

                var cypherText = MypayCrypto.EncryptString(plainText);

                return await Task.FromResult(Ok(new GenerateRsaSignatureResponse { Response = cypherText }));
            }
            catch (Exception)
            {
                return BadRequest(new { Message = "Failed to import key." });
            }
        }

        [HttpGet("decrypt-string")]
        public async Task<IActionResult> DecryptString(string cypherText)
        {
            try
            {

                if (string.IsNullOrWhiteSpace(cypherText))
                    return BadRequest(new { Message = "Input string can not be empty" });

                var plainText = MypayCrypto.DecryptString(cypherText);

                return await Task.FromResult(Ok(new GenerateRsaSignatureResponse { Response = plainText }));
            }
            catch (Exception)
            {
                return BadRequest(new { Message = "Failed to import key." });
            }
        }
    }
}
