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

namespace EasyEncrypt.RSA.Test
{
    [TestClass]
    public class Test1
    {
        const string RandomData = "12345426136136";
        [TestMethod]
        public void TestEncryption()
        {
            EasyRSAKey Key = EasyRSA.CreateKey();
            PrivateRSA RSAPrivate = PrivateRSA.Create(Key.PrivateKey);
            PublicRSA RSAPublic = PublicRSA.Create(Key.PublicKey);

            byte[] Data = Encoding.UTF8.GetBytes(RandomData);
            byte[] EncryptedData = RSAPublic.Encrypt(Data);
            byte[] DecryptedData = RSAPrivate.Decrypt(EncryptedData);

            if (Convert.ToBase64String(Data) != Convert.ToBase64String(DecryptedData)) Assert.Fail();
        }

        [TestMethod]
        public void TestSigning()
        {
            EasyRSAKey Key = EasyRSA.CreateKey();
            PrivateRSA RSAPrivate = PrivateRSA.Create(Key.PrivateKey);
            PublicRSA RSAPublic = PublicRSA.Create(Key.PublicKey);

            byte[] Data = Encoding.UTF8.GetBytes(RandomData);
            Console.WriteLine(Data.Length);
            byte[] SignedData = RSAPrivate.Sign(Data);
            Console.WriteLine(SignedData.Length);

            if (!RSAPublic.Verify(Data, SignedData)) Assert.Fail();
        }
    }
}
