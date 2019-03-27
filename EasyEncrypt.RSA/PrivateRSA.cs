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
    public class PrivateRSA
    {
        /// <summary>
        /// Create class with an already set up provider.
        /// </summary>
        /// <param name="Provider">The RSA provider</param>
        public PrivateRSA(RSACryptoServiceProvider Provider)
            => _Provider = Provider?? throw new ArgumentNullException("Invalid provider, provider is null.");
        /// <summary>
        /// Create class with a key and a custom Provider.
        /// </summary>
        /// <param name="Provider">The RSA provider</param>
        /// <param name="Key">Private RSA key</param>
        public PrivateRSA(RSACryptoServiceProvider Provider, byte[] Key)
        {
            _Provider = Provider??throw new ArgumentNullException("Invalid provider, provider is null.");

            if (Key == null) throw new ArgumentException("Invalid key, key is null.");
            _Provider.ImportCspBlob(Key);
        }
        /// <summary>
        /// Create class with a key.
        /// </summary>
        /// <param name="Key">Private RSA key</param>
        public PrivateRSA(byte[] Key)
        {
            _Provider = new RSACryptoServiceProvider();
            _Provider.ImportCspBlob(Key);
        }

        /// <summary>
        /// Provider for decrypting or signing data.
        /// </summary>
        private RSACryptoServiceProvider _Provider;

        /// <summary>
        /// Decrypt a string and encode with UTF8.
        /// </summary>
        /// <param name="Text">Text to decrypt</param>
        /// <returns>Decrypted text(string encoded with UTF8)</returns>
        public string Decrypt(string Text)
            => Encoding.UTF8.GetString(Decrypt(Convert.FromBase64String(Text)));
        /// <summary>
        /// Decrypt a string.
        /// </summary>
        /// <param name="Text">Text to decrypt</param>
        /// <param name="Encoder">Encoding used to convert byte[] to string</param>
        /// <returns>Decrypted text(string encoded with Encoder)</returns>
        public string Decrypt(string Text,Encoding Encoder)
            => Encoder.GetString(Decrypt(Convert.FromBase64String(Text)));
        /// <summary>
        /// Decrypt a byte[].
        /// </summary>
        /// <param name="Data">Data to decrypt</param>
        /// <returns>Decrypted data</returns>
        public byte[] Decrypt(byte[] Data)
            => _Provider.Decrypt(Data, false);

        /// <summary>
        /// Sign data and use SHA256 as hashingalgorithm.
        /// Hash is needed for long data.
        /// </summary>
        /// <param name="Data">Data to sing</param>
        /// <returns>Signed data</returns>
        public byte[] Sign(byte[] Data)
            => Sign(Data, SHA256.Create());
        /// <summary>
        /// Sign data and use a custom hashingalgorithm.
        /// </summary>
        /// <param name="Data">Data to sign</param>
        /// <param name="Algorithm">Hashing algorithm used to create hash</param>
        /// <returns>Signed data</returns>
        public byte[] Sign(byte[] Data, HashAlgorithm Algorithm)
            => _Provider.SignData(Data, Algorithm);

        /// <summary>
        /// Return the current private key.
        /// </summary>
        /// <returns>Private RSA key</returns>
        public byte[] GetKey()
            => _Provider.ExportCspBlob(true);
    }
}
