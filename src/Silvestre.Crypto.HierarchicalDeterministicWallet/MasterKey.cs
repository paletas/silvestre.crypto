using System.Security.Cryptography;

namespace Silvestre.Crypto.HierarchicalDeterministicWallet
{
    public class MasterKey
    {
        private readonly byte[] _masterKey;

        internal MasterKey(byte[] seed)
        {
            this._masterKey = HMACSHA512.HashData(KeySettings.BITCOIN_KEY_BYTES, seed);

            this.PrivateKey = new ExtendedPrivateKey(this._masterKey, 0);
            this.PublicKey = new ExtendedPublicKey(this.PrivateKey);
        }

        public byte[] Key => _masterKey;

        public ExtendedPrivateKey PrivateKey
        {
            get;
            private set;
        }             

        public ExtendedPublicKey PublicKey
        {
            get;
            private set;
        }
    }
}
