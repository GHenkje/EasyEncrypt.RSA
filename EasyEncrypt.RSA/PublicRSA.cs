/* EasyEncrypt.RSA
 * Copyright (C) 2019 Henkje (henkje@pm.me)
 * 
 * MIT license
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

using System;
using System.Text;
using System.Security.Cryptography;

namespace EasyEncrypt.RSA
{
    public class PublicRSA
    {
        /// <summary>
        /// Create class with an already set up provider.
        /// </summary>
        /// <param name="Provider">The RSA provider</param>
        public PublicRSA(RSACryptoServiceProvider Provider)
            => _Provider = Provider ?? throw new ArgumentNullException("Invalid provider, provider is null.");
        /// <summary>
        /// Create class with a key and a custom Provider.
        /// </summary>
        /// <param name="Provider">The RSA provider</param>
        /// <param name="Key">Public RSA key</param>
        public PublicRSA(RSACryptoServiceProvider Provider, byte[] Key)
        {
            _Provider = Provider ?? throw new ArgumentNullException("Invalid provider, provider is null.");

            if (Key == null) throw new ArgumentException("Invalid key, key is null.");
            _Provider.ImportCspBlob(Key);
        }
        /// <summary>
        /// Create class with a key.
        /// </summary>
        /// <param name="Key">Public RSA key</param>
        public PublicRSA(byte[] Key)
        {
            _Provider = new RSACryptoServiceProvider();
            _Provider.ImportCspBlob(Key);
        }

        /// <summary>
        /// Provider for encrypting or verifying data.
        /// </summary>
        private RSACryptoServiceProvider _Provider;

        /// <summary>
        /// Encrypt a string and decode with UTF8.
        /// </summary>
        /// <param name="Text">Text to encrypt</param>
        /// <returns>Encrypted text(string decoded with UTF8)</returns>
        public string Encrypt(string Text)
            => Convert.ToBase64String(Encrypt(Encoding.UTF8.GetBytes(Text)));
        /// <summary>
        /// Encrypt a string.
        /// </summary>
        /// <param name="Text">Text to encrypt</param>
        /// <param name="Encoder">Encoding used to convert string to byte[]</param>
        /// <returns>Encrypted text(string encoded with Encoder)</returns>
        public string Encrypt(string Text,Encoding Encoder)
            => Convert.ToBase64String(Encrypt(Encoder.GetBytes(Text)));
        /// <summary>
        /// Encrypt a byte[].
        /// </summary>
        /// <param name="Data">Data to encrypt.</param>
        /// <returns>Encrypted data</returns>
        public byte[] Encrypt(byte[] Data)
            =>_Provider.Encrypt(Data, false);

        /// <summary>
        /// Verify signed data and use SHA256 as hashingalgorithm.
        /// </summary>
        /// <param name="Data">Data to compare with SignedData</param>
        /// <param name="SignedData">Already signed data</param>
        /// <returns>true if data is correct, false if data is incorrect</returns>
        public bool Verify(byte[] Data, byte[] SignedData)
            => Verify(Data, SHA256.Create(), SignedData);
        /// <summary>
        /// Verify signed data and use a custom hashingalgorithm.
        /// </summary>
        /// <param name="Data">Data to compare with SignedData</param>
        /// <param name="SignedData">Already signed data</param>
        /// <returns>true if data is correct, false if data is incorrect</returns>
        public bool Verify(byte[] Data, HashAlgorithm Algorithm, byte[] SignedData)
            => _Provider.VerifyData(Data, Algorithm, SignedData);

        /// <summary>
        /// Return the current public key.
        /// </summary>
        /// <returns>Public RSA key</returns>
        public byte[] GetKey()
            => _Provider.ExportCspBlob(false);
    }
}
