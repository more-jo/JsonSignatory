//  --------------------------------------------------------------------------------------------------------------------
//  <copyright file=SignJson.cs company="STRATEC SE">
//    All rights are reserved. Reproduction or transmission in whole or in part, in any form or by any means,
//    electronic, mechanical or otherwise, is prohibited without the prior written consent of the copyright owner.
//  </copyright>
//  --------------------------------------------------------------------------------------------------------------------

namespace JsonSignatory
{
  using System.Diagnostics;
  using System.Security.Cryptography;
  using System.Text;
  using Newtonsoft.Json;

  public class Signature
  {
    public static void Sign(string InputFileName, string SignedFileName, RSA Key)
    {
      string jsonData = File.ReadAllText(InputFileName);

      var hash = ComputeHash(jsonData);

      byte[] signature = Key.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

      // Create a signed object to store the data and the signature.
      var signedData = new
      {
        Data = jsonData,
        Signature = Convert.ToBase64String(signature)
      };

      string signedJson = JsonConvert.SerializeObject(signedData, Formatting.Indented);
      File.WriteAllText(SignedFileName, signedJson);
    }

    public static bool Verify(string SignedFileName, RSA Key)
    {
      string signedJson = File.ReadAllText(SignedFileName);

      dynamic signedData = JsonConvert.DeserializeObject(signedJson);
      string data = signedData.Data;

      byte[] signature = Convert.FromBase64String(signedData.Signature.ToString());

      var hash = ComputeHash(data);

      return Key.VerifyHash(hash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }
    
    public static void SignElements(string inputFileName, string signedFileName, RSA key, string[] elementsToSign)
    {
      if (inputFileName == null) throw new ArgumentNullException(nameof(inputFileName));
      if (signedFileName == null) throw new ArgumentNullException(nameof(signedFileName));
      if (key == null) throw new ArgumentNullException(nameof(key));
      if (elementsToSign == null) throw new ArgumentNullException(nameof(elementsToSign));

      string jsonData = File.ReadAllText(inputFileName);
      var jsonObj = JsonConvert.DeserializeObject<dynamic>(jsonData);

      foreach (var elementToSign in elementsToSign)
      {
        if (jsonObj[elementToSign] != null)
        {
          var hash = ComputeHash(jsonObj[elementToSign].ToString());

          byte[] signature = key.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

          var signatureString = Convert.ToBase64String(signature);
          jsonObj[elementToSign + "_signature"] = signatureString;

          Debug.WriteLine($"Signing element {elementToSign}");
          Debug.WriteLine($"Signing signature: {signatureString}");
          Debug.WriteLine($"Signing hash: {BitConverter.ToString(hash)}");
        }
      }

      string signedJson = JsonConvert.SerializeObject(jsonObj, Formatting.Indented);
      File.WriteAllText(signedFileName, signedJson);
    }

    public static bool VerifyElementwise(string signedFileName, RSA key)
    {
      if (signedFileName == null) throw new ArgumentNullException(nameof(signedFileName));

      string signedText = File.ReadAllText(signedFileName);
      var jsonObject = JsonConvert.DeserializeObject<dynamic>(signedText);

      bool isValid = true;

      foreach (var element in jsonObject)
      {
        var elementName = element.Name;
        if (elementName.EndsWith("_signature"))
        {
          continue;
        }

        string signatureBase64 = jsonObject[elementName + "_signature"];
        if (signatureBase64 != null)
        {
          byte[] signature = Convert.FromBase64String(signatureBase64);

          var hash = ComputeHash(jsonObject[elementName].ToString());

          Debug.WriteLine($"Verification element: {elementName}");
          Debug.WriteLine($"Verification signature: {signatureBase64}");
          Debug.WriteLine($"Verification hash: {BitConverter.ToString(hash)}");

          if (key.VerifyHash(hash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
          {
            Console.WriteLine($"[OK] Signature is valid for {elementName}.");
          }
          else
          {
            isValid = false;
            Console.WriteLine($"Signature for {elementName} is not valid.");
          }
        }
      }

      return isValid;
    }

    private static byte[] ComputeHash(string element)
    {
      byte[] dataBytes = Encoding.UTF8.GetBytes(element);
      
      byte[] hash;
      using (var sha256 = SHA256.Create())
      {
        hash = sha256.ComputeHash(dataBytes);
      }

      return hash;
    }
  }
}