using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Newtonsoft.Json;

namespace JsonSignatory
{
  public class SignVerifyJson
  {
    public static void Main(string[] args)
    {
      VerifyEntireJson();
      Console.WriteLine();
      VerifyJsonElement();
    }

    private static void VerifyEntireJson()
    {
      try
      {
        using RSA key = RSA.Create();

        string jsonFileName = "ExampleCompleteFile.json";
        CreateExample(jsonFileName);
        Console.WriteLine("New JSON file created.");

        string signedJsonFileName = "ExampleCompleteFileSigned.json";
        Signature.Sign(jsonFileName, signedJsonFileName, key);
        Console.WriteLine("JSON file signed.");

        Console.WriteLine("Verifying signature...");
        bool result = Signature.Verify(signedJsonFileName, key);

        if (result)
        {
          Console.WriteLine("The JSON signature is valid.");
        }
        else
        {
          Console.WriteLine("The JSON signature is not valid.");
        }
      }
      catch (CryptographicException e)
      {
        Console.WriteLine(e.Message);
      }
    }

    private static void VerifyJsonElement()
    {
      using RSA key = RSA.Create();

      try
      {
        string file = "ExampleIndividualTags.json";
        string[] elementsToSign = { "tag1", "tag2" };
        CreateExampleWithTags(file, elementsToSign);

        var signedFileName = "ExampleIndividualTagsSignedExample.json";
        Signature.SignElements(
          file, 
          signedFileName, 
          key, 
          elementsToSign);
        Console.WriteLine($"{signedFileName} file signed.");

        Console.WriteLine($"Verifying signature of {signedFileName}");
        bool result = Signature.VerifyElementwise(signedFileName, key);

        if (result)
        {
          Console.WriteLine("The JSON signature is valid.");
        }
        else
        {
          Console.WriteLine("The JSON signature is not valid.");
        }
      }
      catch (CryptographicException e)
      {
        Console.WriteLine(e.Message);
      }
    }


    public static void CreateExample(string FileName)
    {
      var exampleData = new
      {
        MyElement = "Example text to be signed."
      };

      string json = JsonConvert.SerializeObject(exampleData);
      File.WriteAllText(FileName, json);
    }


    public static void CreateExampleWithTags(string FileName, string[] tags)
    {
      var exampleData = new Dictionary<string, Object>
      {
        {"MyElement", "Example text to be signed."},
      };

      foreach (var tag in tags)
      {
        if (tag != null)
        {
          exampleData.Add(tag, "ExampleData");
        }
      }
      
      string json = JsonConvert.SerializeObject(exampleData, Formatting.Indented);
      File.WriteAllText(FileName, json);
    }
  }
}