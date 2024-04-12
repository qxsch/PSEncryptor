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
.\encryptor.ps1 hello -key mysecret
```

## Decrypt
```pwsh
# decrypt a text
.\encryptor.ps1 vTrVExZplQJfV6PCt4++L1MDlHUMjAyhhZMV77PsAjzoy8lojIEx9LfGKjK1akxm -key mysecret -mode Decrypt
```
