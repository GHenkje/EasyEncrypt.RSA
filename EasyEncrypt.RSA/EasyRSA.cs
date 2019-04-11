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
using System.Security.Cryptography;

namespace EasyEncrypt.RSA
{
    public static class EasyRSA
    {
        /// <summary>
        /// Create a new public and private RSA key.
        /// </summary>
        /// <param name="keySize">Keysize of the keys</param>
        /// <returns>The created RSA keys</returns>
        public static EasyRSAKey CreateKey(int keySize = 4096)
        {
            if (keySize <= 0) throw new ArgumentException("Could not create key: Invalid KeySize.");

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(keySize);

            byte[] privateKey = rsa.ExportCspBlob(true);
            byte[] publicKey = rsa.ExportCspBlob(false);

            return new EasyRSAKey() { PrivateKey = privateKey, PublicKey = publicKey };
        }
    }

    /// <summary>
    /// Struct with the private and public RSA keys.
    /// </summary>
    public struct EasyRSAKey
    {
        public byte[] PrivateKey;
        public byte[] PublicKey;
    }
}
