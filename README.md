# PSEncryptor
Simple Powershell AES Encryption and Decryption

## How to download and install?
```pwsh
(Invoke-WebRequest -Uri https://raw.githubusercontent.com/qxsch/PSEncryptor/main/encryptor.ps1).Content | Out-File encryptor.ps1
```

## Usage
```
encryptor.ps1 [-text] <string> [[-key] <string>] [[-mode] Encrypt|Decrypt] [-echo] [<CommonParameters>]
```

## Encrypt
```pwsh
# encrypt a string
.\encryptor.ps1 -text "hello" -key "mysecret"
```

## Decrypt
```pwsh
# decrypt a text
.\encryptor.ps1 -text "eWk9OQLAP7dfCGi1tJs92pMTwGtHK+kI2SWlVcy8vaZwFyokeoyZbk8Uo3yIQ5xfEcqyCYeQMNsad4MRz4wkYC1zEJVtM+jw43Y2TRYwkgrUTiCDsn3In1I3uXN978L7" -key "mysecret" -mode Decrypt
```
