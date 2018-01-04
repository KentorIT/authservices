Configuring authservices to use FIPS compliant encryption algorithms
========

The following entries need to be added to your .NET framework machine configuration.

```xml
  <configuration>
      <mscorlib>
        <cryptographySettings>
          <cryptoNameMapping>
            <cryptoClasses>
              <cryptoClass AES="System.Security.Cryptography.AesCryptoServiceProvider, System.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"/>      
            </cryptoClasses>        
            <nameEntry name="System.Security.Cryptography.SymmetricAlgorithm" class="AES"/>
          </cryptoNameMapping>     
        </cryptographySettings>
      </mscorlib>
  </configuration>
  ```

### 32 Bit Configuration

%windir%\Microsoft.NET\Framework\%frameworkversion%\Config\machine.config

**E.G.** C:\Windows\Microsoft.NET\Framework\v4.0.30319\Config\machine.config


### 64 Bit Configuration

%windir%\Microsoft.NET\Framework64\%frameworkversion%\Config\machine.config

**E.G.** C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config


  