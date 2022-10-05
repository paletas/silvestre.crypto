namespace Silvestre.Crypto.HierarchicalDeterministicWallet
{
    public class HDWallet
    {
        private readonly MasterKey _masterKey;

        public HDWallet(byte[] seed)
        {
            this._masterKey = new MasterKey(seed);
        }

        public HDAccount GetAccount(string path)
        {
            var privateKey = this._masterKey.PrivateKey.DerivePrivateKey(path);
            return new HDAccount(privateKey);
        }
    }
} 