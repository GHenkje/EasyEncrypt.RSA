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
    public class PublicRSA
    {
        /// <summary>
        /// Create class with an already set up provider.
        /// </summary>
        /// <param name="provider">The RSA provider</param>
        public PublicRSA(RSACryptoServiceProvider provider)
            => this.provider = provider ?? throw new ArgumentNullException("Invalid provider, provider is null.");
        /// <summary>
        /// Create class with a key and a custom Provider.
        /// </summary>
        /// <param name="provider">The RSA provider</param>
        /// <param name="key">Public RSA key</param>
        public PublicRSA(RSACryptoServiceProvider provider, byte[] key)
        {
            this.provider = provider ?? throw new ArgumentNullException("Invalid provider, provider is null.");

            if (key == null) throw new ArgumentException("Invalid key, key is null.");
            this.provider.ImportCspBlob(key);
        }
        /// <summary>
        /// Create class with a key.
        /// </summary>
        /// <param name="key">Public RSA key</param>
        public PublicRSA(byte[] key)
        {
            this.provider = new RSACryptoServiceProvider();
            this.provider.ImportCspBlob(key);
        }

        /// <summary>
        /// Provider for encrypting or verifying data.
        /// </summary>
        private readonly RSACryptoServiceProvider provider;

        /// <summary>
        /// Encrypt a string and decode with UTF8.
        /// </summary>
        /// <param name="text">Text to encrypt</param>
        /// <returns>Encrypted text(string decoded with UTF8)</returns>
        public string Encrypt(string text)
            => Convert.ToBase64String(Encrypt(Encoding.UTF8.GetBytes(text)));
        /// <summary>
        /// Encrypt a string.
        /// </summary>
        /// <param name="text">Text to encrypt</param>
        /// <param name="encoder">Encoding used to convert string to byte[]</param>
        /// <returns>Encrypted text(string encoded with Encoder)</returns>
        public string Encrypt(string text, Encoding encoder)
            => Convert.ToBase64String(Encrypt(encoder.GetBytes(text)));
        /// <summary>
        /// Encrypt a byte[].
        /// </summary>
        /// <param name="data">Data to encrypt.</param>
        /// <returns>Encrypted data</returns>
        public byte[] Encrypt(byte[] data)
            => provider.Encrypt(data, false);

        /// <summary>
        /// Verify signed data and use SHA256 as hashingalgorithm.
        /// </summary>
        /// <param name="data">Data to compare with SignedData</param>
        /// <param name="signedData">Already signed data</param>
        /// <returns>true if data is correct, false if data is incorrect</returns>
        public bool Verify(byte[] data, byte[] signedData)
            => Verify(data, SHA256.Create(), signedData);
        /// <summary>
        /// Verify signed data and use a custom hashingalgorithm.
        /// </summary>
        /// <param name="data">Data to compare with SignedData</param>
        /// <param name="signedData">Already signed data</param>
        /// <returns>true if data is correct, false if data is incorrect</returns>
        public bool Verify(byte[] data, HashAlgorithm algorithm, byte[] signedData)
            => provider.VerifyData(data, algorithm, signedData);

        /// <summary>
        /// Return the current public key.
        /// </summary>
        /// <returns>Public RSA key</returns>
        public byte[] GetKey()
            => provider.ExportCspBlob(false);
    }
}
