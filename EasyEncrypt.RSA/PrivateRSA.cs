/* EasyEncrypt.RSA
 * 
 * Copyright (c) 2019 henkje
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
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
        /// <param name="provider">The RSA provider</param>
        public PrivateRSA(RSACryptoServiceProvider provider)
            => this.provider = provider ?? throw new ArgumentNullException("Invalid provider, provider is null.");
        /// <summary>
        /// Create class with a key and a custom Provider.
        /// </summary>
        /// <param name="provider">The RSA provider</param>
        /// <param name="key">Private RSA key</param>
        public PrivateRSA(RSACryptoServiceProvider provider, byte[] key)
        {
            this.provider = provider ?? throw new ArgumentNullException("Invalid provider, provider is null.");

            if (key == null) throw new ArgumentException("Invalid key, key is null.");
            this.provider.ImportCspBlob(key);
        }
        /// <summary>
        /// Create class with a key.
        /// </summary>
        /// <param name="key">Private RSA key</param>
        public PrivateRSA(byte[] key)
        {
            this.provider = new RSACryptoServiceProvider();
            this.provider.ImportCspBlob(key);
        }

        /// <summary>
        /// Provider for decrypting or signing data.
        /// </summary>
        private RSACryptoServiceProvider provider;

        /// <summary>
        /// Decrypt a string and encode with UTF8.
        /// </summary>
        /// <param name="text">Text to decrypt</param>
        /// <returns>Decrypted text(string encoded with UTF8)</returns>
        public string Decrypt(string text)
            => Encoding.UTF8.GetString(Decrypt(Convert.FromBase64String(text)));
        /// <summary>
        /// Decrypt a string.
        /// </summary>
        /// <param name="text">Text to decrypt</param>
        /// <param name="encoder">Encoding used to convert byte[] to string</param>
        /// <returns>Decrypted text(string encoded with Encoder)</returns>
        public string Decrypt(string text, Encoding encoder)
            => encoder.GetString(Decrypt(Convert.FromBase64String(text)));
        /// <summary>
        /// Decrypt a byte[].
        /// </summary>
        /// <param name="data">Data to decrypt</param>
        /// <returns>Decrypted data</returns>
        public byte[] Decrypt(byte[] data)
            => provider.Decrypt(data, false);

        /// <summary>
        /// Sign data and use SHA256 as hashingalgorithm.
        /// Hash is needed for long data.
        /// </summary>
        /// <param name="data">Data to sing</param>
        /// <returns>Signed data</returns>
        public byte[] Sign(byte[] data)
            => Sign(data, SHA256.Create());
        /// <summary>
        /// Sign data and use a custom hashingalgorithm.
        /// </summary>
        /// <param name="data">Data to sign</param>
        /// <param name="algorithm">Hashing algorithm used to create hash</param>
        /// <returns>Signed data</returns>
        public byte[] Sign(byte[] data, HashAlgorithm algorithm)
            => provider.SignData(data, algorithm);

        /// <summary>
        /// Return the current private key.
        /// </summary>
        /// <returns>Private RSA key</returns>
        public byte[] GetKey()
            => provider.ExportCspBlob(true);
    }
}
