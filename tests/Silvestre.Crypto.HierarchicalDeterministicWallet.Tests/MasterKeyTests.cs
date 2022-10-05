using Cryptography.ECDSA;
using FluentAssertions;

namespace Silvestre.Crypto.HierarchicalDeterministicWallet.Tests
{
    public class MasterKeyTests
    {
        [Theory]
        [InlineData("242058fc6241a84555ccb57e8166b3a867b73be4816e7b3bd7d6a34539be0dd36dad61266a4cf7b9141016906871cb7e2cdf8da2208b91a3beafda9f858daeeb", "54463c41cc811470741650fc2980600d2ff95e5ca333a8112d2ae326c77f5c04", "72711ea55a09f032000d45a6616ffd0dff29f418aa6e89a38ca26377a0bfb178")]
        [InlineData("5a85efbd7a84848da3d81a7061174b140075f8d93f08c478eca0ce7be28ead4852226a6275ad9fb5b81be9be9e282edf52ccd45b5113d4f7f02079c5dfb52cb5", "59c62dd69247dc7779cef3f3ae3542c4b7da206c59e23b4d4d5eddc05af93565", "1792324731a704f2280596aaa50a0b743273ab73392425a71330d9fecf19932e")]
        [InlineData("35250c9b5ba43d8f1a1726eb984f92e134c79373d411da424dd6b681fda93527a485c3792c905d1b20e03701172433707f87fd2eb6dc6d661f6c077ec7635a91", "2a2308a144be980afff09b651a37bf3bbba0de1e07331a09610f29d9c62df753", "260bd88e08fd560477915c2101820989f03f7fd21afe5ac3fcfbed9140d68512")]
        public void MasterPrivateKeyDerivationFromSeed(string seed, string expectedPrivateKey, string expectedChainCode)
        {
            byte[] seedBytes = Convert.FromHexString(seed);
            byte[] privateKeyBytes = Convert.FromHexString(expectedPrivateKey);
            byte[] chainCodeBytes = Convert.FromHexString(expectedChainCode);

            MasterKey masterKey = new(seedBytes);             
             
            masterKey.PrivateKey.Key.ToArray().Should()
                .Equal(privateKeyBytes);

            masterKey.PrivateKey.ChainCode.ToArray().Should()
                .Equal(chainCodeBytes);
        }
    }
}