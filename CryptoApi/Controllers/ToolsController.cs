using Core;
using CryptoApi.Dtos;
using CryptoApi.Models;
using Microsoft.AspNetCore.Mvc;
using System.Text;

namespace CryptoApi.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class ToolsController : ControllerBase
    {

        [HttpPost("generate-sha256withrsa-signature-base64")]
        public async Task<IActionResult> GenerateRsaSignature([FromForm] GenerateRsaSignatureRequest request)
        {
            try
            {

                if (!ModelState.IsValid)
                    return BadRequest(ModelState);

                var pvtKey = RsaCryptoUtils.ImportPrivateKeyPem(request.PrivateKey);
                var dataBytes = Encoding.UTF8.GetBytes(request.Data);

                var sigBytes = RsaCryptoUtils.GenerateSignature(dataBytes, pvtKey, RsaCryptoUtils.AlgorithmSHA256withRSA);

                var sigBase64 = Convert.ToBase64String(sigBytes);

                return await Task.FromResult(Ok(new GenerateRsaSignatureResponse { Response = sigBase64 }));
            }
            catch (Exception)
            {
                return BadRequest(new { Message = "Failed to import key." });
            }
        }

        [HttpPost("verify-base64-sha256withrsa-signature")]
        public async Task<IActionResult> VerifyRsaSignature([FromForm] VerifyRsaSignatureRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                var pubKey = RsaCryptoUtils.ImportPublicKeyPem(request.PublicKey);

                var signatureData = Encoding.UTF8.GetBytes(request.SignatureData);
                var signatureBytes = Convert.FromBase64String(request.Base64Signature);

                var isSignatureValid = RsaCryptoUtils.VerifySignature(signatureData, signatureBytes, pubKey, RsaCryptoUtils.AlgorithmSHA256withRSA);

                var response = new VerifyRsaSignatureResponse { VerificationStatus = isSignatureValid ? "Signature is valid" : "Invalid Signature." };

                return await Task.FromResult(Ok(response));
            }
            catch (Exception)
            {
                return BadRequest(new { Message = "Failed to import key." });
            }
        }

        [HttpPost("encrypt-rsa-none-oaepwithsha256andmgf1padding-base64")]
        public async Task<IActionResult> EncryptData([FromForm] EncryptRsaNoneOaepSha256Mgf1PaddingRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                var pubKey = RsaCryptoUtils.ImportPublicKeyPem(request.PublicKey);
                var plainBytes = Encoding.UTF8.GetBytes(request.Data);

                var cipheredBytes = RsaCryptoUtils.EncryptData(plainBytes, pubKey, RsaCryptoUtils.AlgorithmRsaNoneOaepWithSha256AndMgf1Padding);

                var cipheredBase64 = Convert.ToBase64String(cipheredBytes);

                return await Task.FromResult(Ok(new EncryptRsaNoneOaepSha256Mgf1PaddingResponse { EncryptedData = cipheredBase64 }));
            }
            catch (Exception)
            {
                return BadRequest(new { Message = "Failed to import key." });
            }
        }

        [HttpPost("decrypt-base64-rsa-none-oaepwithsha256andmgf1padding")]
        public async Task<IActionResult> DecryptData([FromForm] DecryptRsaNoneOaepSha256Mgf1PaddingRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                var pvtKey = RsaCryptoUtils.ImportPrivateKeyPem(request.PrivateKey);
                var cipheredBytes = Convert.FromBase64String(request.CipheredData);

                var decipheredBytes = RsaCryptoUtils.DecryptData(cipheredBytes, pvtKey, RsaCryptoUtils.AlgorithmRsaNoneOaepWithSha256AndMgf1Padding);

                var plainText = Encoding.UTF8.GetString(decipheredBytes);

                return await Task.FromResult(Ok(new DecryptRsaNoneOaepSha256Mgf1PaddingResponse { DecryptedData = plainText }));
            }
            catch (Exception)
            {
                return BadRequest(new { Message = "Failed to import key." });
            }
        }

        [HttpPost("decrypt-base64-rsa-ecb-oaepwithsha256andmgf1padding")]
        public async Task<IActionResult> DecryptDataEcb([FromForm] DecryptRsaNoneOaepSha256Mgf1PaddingRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                var pvtKey = RsaCryptoUtils.ImportPrivateKeyPem(request.PrivateKey);
                var cipheredBytes = Convert.FromBase64String(request.CipheredData);

                var decipheredBytes = RsaCryptoUtils.DecryptData(cipheredBytes, pvtKey, RsaCryptoUtils.AlgorithmRsaEcbOaepWithSha256AndMgf1Padding);

                var plainText = Encoding.UTF8.GetString(decipheredBytes);

                return await Task.FromResult(Ok(new DecryptRsaNoneOaepSha256Mgf1PaddingResponse { DecryptedData = plainText }));
            }
            catch (Exception)
            {
                return BadRequest(new { Message = "Failed to import key." });
            }
        }
    }
}
