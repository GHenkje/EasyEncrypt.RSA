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
using System.Security.Cryptography;

namespace EasyEncrypt.RSA
{
    public static class EasyRSA
    {
        /// <summary>
        /// Create a new public and private RSA key.
        /// </summary>
        /// <param name="KeySize">Keysize of the keys</param>
        /// <returns>The created RSA keys</returns>
        public static EasyRSAKey CreateKey(int KeySize = 2048)
        {
            if (KeySize <= 0) throw new ArgumentException("Could not create key: Invalid KeySize.");

            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(KeySize);

            byte[] PrivateKey = RSA.ExportCspBlob(true);
            byte[] PublicKey = RSA.ExportCspBlob(false);

            return new EasyRSAKey() { PrivateKey = PrivateKey, PublicKey = PublicKey };
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
