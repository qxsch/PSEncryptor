# PSEncryptor
Simple Powershell AES Encryption and Decryption

## How to download and install?
```pwsh
(Invoke-WebRequest -Uri https://raw.githubusercontent.com/qxsch/PSEncryptor/main/encryptor.ps1).Content | Out-File encryptor.ps1
```

## Usage
```
encryptor.ps1 [-text] <string> [[-key] <string>] [[-mode] Encrypt|Decrypt] [-FromClipboard] [-ToClipboard] [-PromptKey] [-echo] [<CommonParameters>]
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

## Pipeline Streaming
For faster file encryption, use `-Raw` to process the entire file as a single string:
```pwsh
Get-Content .\data.txt -Raw | .\encryptor.ps1 -key "mysecret" | Set-Content .\data-enc.txt
Get-Content .\data-enc.txt -Raw | .\encryptor.ps1 -key "mysecret" -mode Decrypt | Set-Content .\data-dec.txt
```

## Clipboard Integration
Read from the clipboard, encrypt, and copy the result back:
```pwsh
.\encryptor.ps1 -FromClipboard -ToClipboard -key "mysecret"
```

Encrypt a string and send only to the clipboard (no pipeline/console output):
```pwsh
.\encryptor.ps1 -text "hello" -key "mysecret" -ToClipboard
```
