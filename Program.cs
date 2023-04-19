/**
 * This program was written with the help of ChatGPT.  
 * Feel free to download and modify it any way you like.
 * It would be cool to give credit but whatevs.
 * 
 */

using System;
using System.IO;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;

namespace PgpEncryptionExample
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Do you want to (E)ncrypt or (D)ecrypt?");
            string operation = Console.ReadLine()?.ToUpperInvariant();

            if (operation == "E")
            {
                Console.WriteLine("Enter the path to the input file:");
                string inputFile = Console.ReadLine();

                Console.WriteLine("Enter the path to the public key file:");
                string publicKeyFile = Console.ReadLine();

                Console.WriteLine("Enter the output path for the encrypted file:");
                string outputFile = Console.ReadLine();

                try
                {
                    EncryptFile(inputFile, publicKeyFile, outputFile);
                    Console.WriteLine("Encryption completed successfully!");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                }
            }
            else if (operation == "D")
            {
                Console.WriteLine("Enter the path to the encrypted input file:");
                string inputFile = Console.ReadLine();

                Console.WriteLine("Enter the path to the private key file:");
                string privateKeyFile = Console.ReadLine();

                Console.WriteLine("Enter the passphrase for the private key:");
                string passphrase = Console.ReadLine();

                Console.WriteLine("Enter the output path for the decrypted file:");
                string outputFile = Console.ReadLine();

                try
                {
                    DecryptFile(inputFile, privateKeyFile, passphrase, outputFile);
                    Console.WriteLine("Decryption completed successfully!");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                }
            }
            else
            {
                Console.WriteLine("Invalid operation. Please enter 'E' for encryption or 'D' for decryption.");
            }
        }
        private static void DecryptFile(string inputFile, string privateKeyFile, string passphrase, string outputFile)
        {
            using (Stream outputStream = File.Create(outputFile),
                           privateKeyStream = File.OpenRead(privateKeyFile),
                           inputFileStream = File.OpenRead(inputFile))
            {
                PgpPrivateKey privateKey = ReadPrivateKey(privateKeyStream, passphrase);
                PgpDecrypt decryptor = new PgpDecrypt(inputFileStream, outputStream, privateKey, passphrase.ToCharArray());
                decryptor.Decrypt();
            }
        }

        private static void EncryptFile(string inputFile, string publicKeyFile, string outputFile)
        {
            using (Stream outputStream = File.Create(outputFile),
                           publicKeyStream = File.OpenRead(publicKeyFile),
                           inputFileStream = File.OpenRead(inputFile))
            {
                PgpPublicKey publicKey = ReadPublicKey(publicKeyStream);
                PgpEncryptionKeys encryptionKeys = new PgpEncryptionKeys(publicKey);
                PgpEncrypt encryptor = new PgpEncrypt(inputFileStream, outputStream, encryptionKeys);
                encryptor.Encrypt();
            }
        }
        private static PgpPrivateKey ReadPrivateKey(Stream inputStream, string passphrase)
        {
            using (Stream keyIn = inputStream)
            {
                PgpSecretKeyRingBundle secretKeyRingBundle = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(keyIn));
                foreach (PgpSecretKeyRing keyRing in secretKeyRingBundle.GetKeyRings())
                {
                    foreach (PgpSecretKey key in keyRing.GetSecretKeys())
                    {
                        if (key.IsPrivateKeyEmpty)
                        {
                            continue;
                        }

                        try
                        {
                            PgpPrivateKey privateKey = key.ExtractPrivateKey(passphrase.ToCharArray());
                            if (privateKey != null)
                            {
                                return privateKey;
                            }
                        }
                        catch (PgpException)
                        {
                            // Ignore this exception and continue searching for a valid private key.
                        }
                    }
                }
            }

            throw new ArgumentException("No valid private key found in the provided private key file.");
        }
        private static PgpPublicKey ReadPublicKey(Stream inputStream)
        {
            using (Stream keyIn = inputStream)
            {
                PgpPublicKeyRingBundle publicKeyRingBundle = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(keyIn));
                foreach (PgpPublicKeyRing keyRing in publicKeyRingBundle.GetKeyRings())
                {
                    foreach (PgpPublicKey key in keyRing.GetPublicKeys())
                    {
                        if (key.IsEncryptionKey)
                        {
                            return key;
                        }
                    }
                }
            }

            throw new ArgumentException("No encryption key found in the provided public key file.");
        }
    }
    public class PgpEncryptionKeys
    {
        public PgpPublicKey PublicKey { get; }

        public PgpEncryptionKeys(PgpPublicKey publicKey)
        {
            PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey), "Public key is required.");
        }
    }
    public class PgpEncrypt
    {
        private readonly PgpEncryptionKeys _encryptionKeys;
        private readonly Stream _outputStream;
        private readonly Stream _inputStream;

        public PgpEncrypt(Stream inputStream, Stream outputStream, PgpEncryptionKeys encryptionKeys)
        {
            _inputStream = inputStream;
            _outputStream = outputStream;
            _encryptionKeys = encryptionKeys;
        }

        public void Encrypt()
        {
            if (_encryptionKeys == null)
            {
                throw new ArgumentException("Encryption keys not set.");
            }

            using (Stream armoredStream = new ArmoredOutputStream(_outputStream))
            {
                PgpEncryptedDataGenerator encGen = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, true, new SecureRandom());
                encGen.AddMethod(_encryptionKeys.PublicKey);

                using (Stream encryptedStream = encGen.Open(armoredStream, new byte[1 << 16]))
                {
                    PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
                    using (Stream compressedStream = comData.Open(encryptedStream))
                    {
                        PgpLiteralDataGenerator literalDataGen = new PgpLiteralDataGenerator();
                        using (Stream literalDataStream = literalDataGen.Open(compressedStream, PgpLiteralData.Binary, "_CONSOLE", _inputStream.Length, DateTime.UtcNow))
                        {
                            byte[] buffer = new byte[1 << 16];
                            int bytesRead;
                            while ((bytesRead = _inputStream.Read(buffer, 0, buffer.Length)) > 0)
                            {
                                literalDataStream.Write(buffer, 0, bytesRead);
                            }
                        }
                    }
                }
            }
        }
    }

    public class PgpDecrypt
    {
        private readonly Stream _inputStream;
        private readonly Stream _outputStream;
        private readonly PgpPrivateKey _privateKey;
        private readonly char[] _passphrase;

        public PgpDecrypt(Stream inputStream, Stream outputStream, PgpPrivateKey privateKey, char[] passphrase)
        {
            _inputStream = inputStream;
            _outputStream = outputStream;
            _privateKey = privateKey;
            _passphrase = passphrase;
        }
 
public void Decrypt()
        {
            if (_privateKey == null)
            {
                throw new ArgumentException("Private key not set.");
            }

            using (Stream inputStream = PgpUtilities.GetDecoderStream(_inputStream))
            {
                PgpObjectFactory pgpObjFactory = new PgpObjectFactory(inputStream);
                PgpEncryptedDataList encryptedDataList;

                PgpObject pgpObj = pgpObjFactory.NextPgpObject();

                if (pgpObj is PgpEncryptedDataList)
                {
                    encryptedDataList = (PgpEncryptedDataList)pgpObj;
                }
                else
                {
                    encryptedDataList = (PgpEncryptedDataList)pgpObjFactory.NextPgpObject();
                }

                PgpPublicKeyEncryptedData publicKeyData = null;

                foreach (PgpPublicKeyEncryptedData pked in encryptedDataList.GetEncryptedDataObjects())
                {
                    try
                    {
                        if (pked.KeyId == _privateKey.KeyId)
                        {
                            publicKeyData = pked;
                            break;
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"GetDataStream Error: {e.Message}");
                        Console.WriteLine($"\n\nDebug note: maybe check the way you've generated your keys.  Certain key standards are not supported by bouncycastle.\n\n");
                        Console.WriteLine($"GetDataStream Stack Trace: {e.StackTrace}");
                    }
                }

                if (publicKeyData == null)
                {
                    throw new ArgumentException("No matching key found.");
                }

                Stream clearDataStream = publicKeyData.GetDataStream(_privateKey);
                PgpObjectFactory clearObjectFactory = new PgpObjectFactory(clearDataStream);

                PgpObject message = clearObjectFactory.NextPgpObject();

                if (message is PgpCompressedData compressedData)
                {
                    PgpObjectFactory compressedObjectFactory = new PgpObjectFactory(compressedData.GetDataStream());
                    message = compressedObjectFactory.NextPgpObject();
                }

                if (message is PgpLiteralData literalData)
                {
                    using (Stream uncDataStream = literalData.GetInputStream())
                    {
                        byte[] buffer = new byte[1 << 16];
                        int bytesRead;

                        while ((bytesRead = uncDataStream.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            _outputStream.Write(buffer, 0, bytesRead);
                        }
                    }
                }
                else
                {
                    throw new ArgumentException("Message is not literal data.");
                }
            }
        }
    }

}