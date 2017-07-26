using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Json
{
    class BufferedCipherTransform : ICryptoTransform
    {
        private readonly BufferedAsymmetricBlockCipher _cipher;

        public int InputBlockSize { get; private set; }
        public int OutputBlockSize { get; private set; }
        public bool CanTransformMultipleBlocks { get { return false; } }
        public bool CanReuseTransform { get { return true; } }

        public BufferedCipherTransform(BufferedAsymmetricBlockCipher cipher)
        {
            _cipher = cipher;
            InputBlockSize = _cipher.GetBlockSize();
            OutputBlockSize = _cipher.GetOutputSize(0);
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            var len = _cipher.ProcessBytes(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
            return _cipher.DoFinal(inputBuffer, inputOffset, len, outputBuffer, outputOffset);
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            return _cipher.DoFinal(inputBuffer, inputOffset, inputCount);
        }

        public void Dispose()
        {
            _cipher.Reset();
            GC.SuppressFinalize(this);
        }


    }
}
