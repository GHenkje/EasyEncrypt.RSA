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

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;
using System;
using System.Security.Cryptography;

namespace EasyEncrypt.RSA.Test
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void TestEncryption()
        {
            const string DATA = "Input";

            EasyRSAKey Key = EasyRSA.CreateKey();
            PrivateRSA RSAPrivate = new PrivateRSA(Key.PrivateKey);
            PublicRSA RSAPublic = new PublicRSA(Key.PublicKey);

            byte[] Data = Encoding.UTF8.GetBytes(DATA);
            byte[] EncryptedData = RSAPublic.Encrypt(Data);
            byte[] DecryptedData = RSAPrivate.Decrypt(EncryptedData);

            if (Convert.ToBase64String(Data) != Convert.ToBase64String(DecryptedData)) Assert.Fail();
        }

        [TestMethod]
        public void TestSigning()
        {
            byte[] DATA = Encoding.UTF8.GetBytes("12345");

            EasyRSAKey Key = EasyRSA.CreateKey();

            PrivateRSA RSAPrivate = new PrivateRSA(Key.PrivateKey);
            PublicRSA RSAPublic = new PublicRSA(Key.PublicKey);

            byte[] SignedData = RSAPrivate.Sign(DATA);
            bool Verify = RSAPublic.Verify(DATA, SignedData);

            byte[] SignedData2 = RSAPrivate.Sign(DATA,SHA1.Create());
            bool Verify2 = RSAPublic.Verify(DATA,SHA1.Create(), SignedData);

            if (!Verify || Verify2)
                Assert.Fail();
        }
    }
}
