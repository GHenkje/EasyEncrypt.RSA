/* EasyEncrypt.RSA.Test
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

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;
using System.Text;
using System;

namespace EasyEncrypt.RSA.Test
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void TestEncryption()
        {
            EasyRSAKey key = EasyRSA.CreateKey();
            PrivateRSA RSAPrivate = new PrivateRSA(key.PrivateKey);
            PublicRSA RSAPublic = new PublicRSA(key.PublicKey);

            byte[] data = Encoding.UTF8.GetBytes("Input");
            byte[] encryptedData = RSAPublic.Encrypt(data);
            byte[] decryptedData = RSAPrivate.Decrypt(encryptedData);

            Assert.AreEqual(Convert.ToBase64String(data), Convert.ToBase64String(decryptedData));
        }

        [TestMethod]
        public void TestSigning()
        {
            byte[] data = Encoding.UTF8.GetBytes("12345");

            EasyRSAKey key = EasyRSA.CreateKey();
            
            PrivateRSA RSAPrivate = new PrivateRSA(key.PrivateKey);
            PublicRSA RSAPublic = new PublicRSA(key.PublicKey);

            byte[] signedData = RSAPrivate.Sign(data);
            bool verify = RSAPublic.Verify(data, signedData);

            byte[] signedData2 = RSAPrivate.Sign(data, SHA1.Create());
            bool verify2 = RSAPublic.Verify(data, SHA1.Create(), signedData);

            if (!verify || verify2)
                Assert.Fail();
        }
    }
}
