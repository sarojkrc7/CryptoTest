using Core;
using CryptoApi.Dtos;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Asn1.Ocsp;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

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

        [HttpGet("encryption-from-key")]
        public async Task<IActionResult> EncryptionFromKey(string plainText, string secretKey)
        {
            try
            {

                if (string.IsNullOrWhiteSpace(plainText))
                    return BadRequest(new { Message = "Input string can not be empty" });
                if (string.IsNullOrWhiteSpace(secretKey))
                    return BadRequest(new { Message = "Key can not be empty" });

                var cypherText = MypayCrypto.EncryptionFromKey(plainText,secretKey);

                return await Task.FromResult(Ok(new GenerateRsaSignatureResponse { Response = cypherText }));
            }
            catch (Exception)
            {
                return BadRequest(new { Message = "Failed to import key." });
            }
        }

        [HttpGet("decryption-from-key")]
        public async Task<IActionResult> DecryptionFromkey(string cypherText, string secretKey)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(cypherText))
                    return BadRequest(new { Message = "Input string can not be empty" });
                if (string.IsNullOrWhiteSpace(secretKey))
                    return BadRequest(new { Message = "Key can not be empty" });

                var plainText = MypayCrypto.DecryptionFromKey(cypherText,secretKey);

                return await Task.FromResult(Ok(new GenerateRsaSignatureResponse { Response = plainText }));
            }
            catch (Exception)
            {
                return BadRequest(new { Message = "Failed to import key." });
            }
        }

        [HttpGet("encode-to-base64string")]
        public async Task<IActionResult> Base64Encode(string data)
        {
            try
            {

                if (string.IsNullOrWhiteSpace(data))
                    return BadRequest(new { Message = "Input string can not be empty" });

                var result = MypayCrypto.base64Encode(data);

                return await Task.FromResult(Ok(new GenerateRsaSignatureResponse { Response = result }));
            }
            catch (Exception)
            {
                return BadRequest(new { Message = "Failed to import key." });
            }
        }

        [HttpGet("decode-from-base64string")]
        public async Task<IActionResult> DecodeBase64(string data)
        {
            try
            {

                if (string.IsNullOrWhiteSpace(data))
                    return BadRequest(new { Message = "Input string can not be empty" });

                var result = MypayCrypto.base64Decode(data);

                return await Task.FromResult(Ok(new GenerateRsaSignatureResponse { Response = result }));
            }
            catch (Exception)
            {
                return BadRequest(new { Message = "Failed to import key." });
            }
        }

        [HttpGet("minify-json-payload")]
        public async Task<IActionResult> MinifyJson(string data)
        {
            try
            {

                if (string.IsNullOrWhiteSpace(data))
                    return BadRequest(new { Message = "Input string can not be empty" });

                var result = MypayCrypto.CompressJsonPayload(data);

                return await Task.FromResult(Ok(new GenerateRsaSignatureResponse { Response = result }));
            }
            catch (Exception)
            {
                return BadRequest(new { Message = "Failed to import key." });
            }
        }

        [HttpPost("compress")]
        public async Task<IActionResult> CompressJson()
        {
            using var reader = new StreamReader(Request.Body);
            string rawJson = await reader.ReadToEndAsync();

            try
            {
                // Parse and re-serialize (minify) JSON
                using var jsonDoc = JsonDocument.Parse(rawJson);
                var minifiedJson = JsonSerializer.Serialize(jsonDoc.RootElement);

                // Deserialize back to object so response is application/json
                var minifiedObj = JsonSerializer.Deserialize<object>(minifiedJson);

                return Ok(minifiedObj);
            }
            catch (JsonException)
            {
                return BadRequest("Invalid JSON input.");
            }
        }

        [HttpPost("minify")]
        public IActionResult MinifyJson([FromBody] JsonNode inputJson)
        {
            // Serialize the JsonNode using compact formatting (no extra whitespace)
            string minifiedJson = inputJson.ToJsonString(new JsonSerializerOptions
            {
                WriteIndented = false
            });

            // Parse the minified string back into a JSON object to return as an object (not string)
            JsonNode? responseObject = JsonNode.Parse(minifiedJson);
            return Ok(responseObject);
        }

        [HttpGet("generate-rsa-keys")]
        public IActionResult GenerateRsaKeys()
        {
            (string privatekey, string publickey) = MypayCrypto.GenerateRsaKeyPair();
            return Ok(new { PrivateKey = privatekey, PublicKey = publickey });
        }
    }
}
