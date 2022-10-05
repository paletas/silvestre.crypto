using SimpleBase;

namespace Silvestre.Crypto.HierarchicalDeterministicWallet
{
    public class HDAccount
    {
        internal HDAccount(ExtendedPrivateKey privateKey)
        {
            PrivateKey = privateKey;
        }

        public ExtendedPrivateKey PrivateKey { get; }

        public ExtendedPublicKey PublicKey => new(PrivateKey);

        public string Address => Base58.Bitcoin.Encode(this.PublicKey.Key);
    }
}
