//----------------------------------------------------------------------------------------------
// <copyright file="CertContextHandle.cs" company="Microsoft">
// Copyright (c) Microsoft.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace SSLHelper
{
    class Program
    {
        static bool OnRemoteCertificateReceived(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            Console.WriteLine("Remote Certificate Received!");
            SslStream stream = (SslStream)sender;

            bool ok = true;
            if (sslPolicyErrors != 0)
            {
                Console.WriteLine($"SSL Policy ERRORS!! {sslPolicyErrors.ToString()}");
                ok = false;
            }

            string indent = "";
            foreach (var el in chain.ChainElements)
            {
                var c = (X509Certificate2)el.Certificate;

                Console.WriteLine($"{indent}Subject={c.Subject}, Expires: {c.GetExpirationDateString()}, KeyAlgorithm={c.GetKeyAlgorithmParametersString()} Issuer={c.Issuer}");

                string filename = c.Subject.Replace("CN=", "").Replace("*", "") + ".cer";
                Console.WriteLine($"{indent}Saving Certificate public key data: {filename}");
                var certBytes = c.Export(X509ContentType.Cert);
                File.WriteAllBytes(filename, certBytes);

                var s = el.ChainElementStatus;
                foreach (var status in s.Where(x => x.Status != 0))
                {
                    Console.WriteLine($"{indent}Cert Status: {status.Status}, {status.StatusInformation}");
                    ok = false;
                }

                Console.WriteLine();
                indent += "  ";
            }

            bool buildsOk = chain.Build((X509Certificate2)certificate);
            if (!buildsOk)
            {
                Console.WriteLine("Building Certificate chain failed!");
                ok = false;
            }
            foreach (var status in chain.ChainStatus)
            {
                Console.WriteLine($"Chain Status: {status.Status}, {status.StatusInformation}");
            }

            if (ok) Console.WriteLine("No errors - certificate validation passed!");
            return ok;
        }

        static X509Certificate OnClientCertificateRequested(
            object sender, 
            string targetHost, 
            X509CertificateCollection localCertificates, 
            X509Certificate remoteCertificate, 
            string[] acceptableIssuers)
        {
            Console.WriteLine("Not using a client certificate");
            return null;
        }

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Usage: SSLHelper [hostname] [port]");
                Console.WriteLine("port defaults to 443 if not specified");
                return;
            }

            string hostname = args[0];
            int port = args.Length == 1 ? 443 : int.Parse(args[1]);

            var addr = Dns.GetHostAddresses(hostname).First();
            Console.WriteLine($"DNS resolved {hostname} to address {addr}");
            IPEndPoint remoteEP = new IPEndPoint(addr, port);

            Console.WriteLine($"Creating TCP Socket and NetworkStream");
            Socket s;
            Stream tcpStream;
            try
            {
                s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                s.Connect(remoteEP);
                tcpStream = new NetworkStream(s, ownsSocket: true);
            }
            catch (Exception e)
            {
                Console.WriteLine($"Network Stream creation failed with {e.GetType()}: {e.ToString()}");
                return;
            }

            using (SslStream sslStream = new SslStream(tcpStream, false, OnRemoteCertificateReceived, OnClientCertificateRequested, EncryptionPolicy.RequireEncryption))
            {
                try
                {
                    sslStream.AuthenticateAsClient(hostname);

                    Console.WriteLine($"TransportContext: {sslStream.TransportContext}");
                    Console.WriteLine($"Protocol: {sslStream.SslProtocol}");

                    Console.WriteLine($"KeyExchangeAlgorithm: {sslStream.KeyExchangeAlgorithm}");
                    Console.WriteLine($"KeyExchangeStrength: {sslStream.KeyExchangeStrength}");

                    Console.WriteLine($"CipherAlgorithm: {sslStream.CipherAlgorithm}");
                    Console.WriteLine($"CipherStrength: {sslStream.CipherStrength}");

                    Console.WriteLine($"HashAlgorithm: {sslStream.HashAlgorithm}");
                    Console.WriteLine($"HashStrength: {sslStream.HashStrength}");
                }
                catch (Exception e)
                {
                    Console.WriteLine($"SSL Stream creation failed with {e.GetType()}: {e.ToString()}");
                    return;
                }
            }

            Console.WriteLine("All checks passed!");
        }
    }
}
