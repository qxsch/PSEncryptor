<#
.SYNOPSIS
Encrypts or decrypts a string using AES-256 encryption with HMAC-SHA256 authentication.

.DESCRIPTION
This script encrypts or decrypts a string using AES-256-CBC encryption with PBKDF2-SHA256
key derivation and HMAC-SHA256 encrypt-then-MAC authentication to prevent tampering.

.PARAMETER text
The text to be encrypted or decrypted. Can also be used to pipe text to the script.

.PARAMETER key
The key to be used for encryption. If not provided, a default key "MySecretKey" is used.

.PARAMETER PromptKey
When specified, prompts for the key interactively using a masked input. The key will not appear
in command history or process arguments. Overrides the -key parameter.

.PARAMETER mode
Should it encrypt or decrypt the provided text. Default is Encrypt. Use Decrypt to decrypt the text.

.PARAMETER DerivationIterations
The number of PBKDF2 iterations for key derivation. Default is 100000. Minimum is 10000.

.PARAMETER echo
This switch is used to write the output to the console.

.OUTPUTS
The encrypted or decrypted text. If the -echo switch is used, the output is written to the console.

.EXAMPLE
./encryptor.ps1 -text "Hello, World!" -key "mysecret"
This example encrypts the string "Hello, World!" using the key "mysecret".

.EXAMPLE
.\encryptor.ps1 "<encrypted-text>" -key "mysecret" -mode Decrypt
This example decrypts the string back using the key "mysecret".

.EXAMPLE
.\encryptor.ps1 -text "Hello, World!" -PromptKey
This example prompts for the key interactively (masked input) so it doesn't appear in history.

.NOTES
Uses AES-256-CBC with PBKDF2-SHA256 key derivation (100k iterations) and HMAC-SHA256
encrypt-then-MAC authentication. All cryptographic objects are disposed and key material
is zeroed after use.
#>


param(
    [Parameter(Position=0,mandatory=$true, ValueFromPipeline=$true)]
    [string]$text,
    
    [Parameter(Position=1,mandatory=$false)]
    [string]$key="MySecretKey",

    [Parameter(Position=2,mandatory=$false)]
    [ValidateSet("Encrypt","Decrypt")]
    [string]$mode="Encrypt",

    [int32]$DerivationIterations = 100000,

    [switch]$PromptKey,

    [switch]$echo
)

if ($PromptKey) {
    $secureKey = Read-Host -Prompt "Enter key" -AsSecureString
    $key = [System.Net.NetworkCredential]::new('', $secureKey).Password
}

if ([string]::IsNullOrEmpty($key)) {
    Throw "Key cannot be empty."
}

if($DerivationIterations -lt 10000) {
    Throw "DerivationIterations cannot be below 10,000."
}
if($DerivationIterations -gt 2100000000) {
    Throw "DerivationIterations cannot be above 2'100'000'000."
}

function Encrypt-String {
    param (
        [string]$clearText,
        [string]$key,
        [int32]$DerivationIterations = 100000
    )

    # Constants for encryption
    $KeySize = 256
    $BlockSize = 128

    # Generate random bytes for salt and initialization vector (IV)
    $saltBytes = New-Object byte[] ($KeySize / 8)
    $ivBytes = New-Object byte[] ($BlockSize / 8)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($saltBytes)
        $rng.GetBytes($ivBytes)
    }
    finally {
        $rng.Dispose()
    }

    # Derive encryption key and HMAC key from the password and salt using PBKDF2-SHA256
    $password = [Security.Cryptography.Rfc2898DeriveBytes]::new($key, $saltBytes, $DerivationIterations, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $keyBytes = $password.GetBytes($KeySize / 8)
    $hmacKeyBytes = $password.GetBytes($KeySize / 8)

    $symmetricKey = $null
    $encryptor = $null
    $memoryStream = $null
    $cryptoStream = $null
    $streamWriter = $null

    try {
        # Create AES-256 encryption
        $symmetricKey = [System.Security.Cryptography.Aes]::Create()
        $symmetricKey.KeySize = $KeySize
        $encryptor = $symmetricKey.CreateEncryptor($keyBytes, $ivBytes)

        # Encrypt the clear text
        $memoryStream = [System.IO.MemoryStream]::new()
        $cryptoStream = [System.Security.Cryptography.CryptoStream]::new($memoryStream, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
        $streamWriter = [System.IO.StreamWriter]::new($cryptoStream)
        $streamWriter.Write($clearText)
        $streamWriter.Close()

        $encryptedBytes = $memoryStream.ToArray()

        # Combine salt + IV + ciphertext as the payload
        $payload = $saltBytes + $ivBytes + $encryptedBytes

        # Compute HMAC-SHA256 over the payload (encrypt-then-MAC)
        $hmac = [System.Security.Cryptography.HMACSHA256]::new($hmacKeyBytes)
        try {
            $mac = $hmac.ComputeHash($payload)
        }
        finally {
            $hmac.Dispose()
        }

        # Final output: payload + HMAC tag
        $result = $payload + $mac

        return [Convert]::ToBase64String($result)
    }
    finally {
        if ($null -ne $streamWriter) { $streamWriter.Dispose() }
        if ($null -ne $cryptoStream) { $cryptoStream.Dispose() }
        if ($null -ne $memoryStream) { $memoryStream.Dispose() }
        if ($null -ne $encryptor) { $encryptor.Dispose() }
        if ($null -ne $symmetricKey) { $symmetricKey.Dispose() }
        if ($null -ne $password) { $password.Dispose() }
        if ($null -ne $keyBytes) { [Array]::Clear($keyBytes, 0, $keyBytes.Length) }
        if ($null -ne $hmacKeyBytes) { [Array]::Clear($hmacKeyBytes, 0, $hmacKeyBytes.Length) }
    }
}

function Decrypt-CipherText {
    param (
        [string]$cipherText,
        [string]$key,
        [int32]$DerivationIterations = 100000
    )

    # Constants for decryption
    $KeySize = 256
    $BlockSize = 128
    $MacSize = 256

    # Decode the base64-encoded data
    $allBytes = [Convert]::FromBase64String($cipherText)

    $saltSize = $KeySize / 8       # 32 bytes
    $ivSize = $BlockSize / 8       # 16 bytes
    $macSize = $MacSize / 8        # 32 bytes
    $minLength = $saltSize + $ivSize + $macSize + 1

    if ($allBytes.Length -lt $minLength) {
        Throw "Invalid ciphertext: data is too short."
    }

    # Extract salt, IV, encrypted data, and HMAC tag
    $saltBytes = $allBytes[0..($saltSize - 1)]
    $ivBytes = $allBytes[$saltSize..($saltSize + $ivSize - 1)]
    $encryptedBytes = $allBytes[($saltSize + $ivSize)..($allBytes.Length - $macSize - 1)]
    $receivedMac = $allBytes[($allBytes.Length - $macSize)..($allBytes.Length - 1)]
    $payload = $allBytes[0..($allBytes.Length - $macSize - 1)]

    # Derive encryption key and HMAC key
    $password = [Security.Cryptography.Rfc2898DeriveBytes]::new($key, $saltBytes, $DerivationIterations, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $keyBytes = $password.GetBytes($KeySize / 8)
    $hmacKeyBytes = $password.GetBytes($KeySize / 8)

    $aesAlg = $null
    $decryptor = $null
    $msDecrypt = $null
    $csDecrypt = $null
    $srDecrypt = $null

    try {
        # Verify HMAC-SHA256 before decrypting (authenticate-then-decrypt)
        $hmac = [System.Security.Cryptography.HMACSHA256]::new($hmacKeyBytes)
        try {
            $computedMac = $hmac.ComputeHash($payload)
        }
        finally {
            $hmac.Dispose()
        }

        # Constant-time comparison to prevent timing attacks
        $diff = 0
        for ($i = 0; $i -lt $computedMac.Length; $i++) {
            $diff = $diff -bor ($computedMac[$i] -bxor $receivedMac[$i])
        }
        if ($diff -ne 0) {
            Throw "Authentication failed: ciphertext has been tampered with or the key is incorrect."
        }

        # Create AES-256 decryptor
        $aesAlg = [Security.Cryptography.Aes]::Create()
        $aesAlg.KeySize = $KeySize
        $decryptor = $aesAlg.CreateDecryptor($keyBytes, $ivBytes)

        # Decrypt the ciphertext
        $msDecrypt = [System.IO.MemoryStream]::new($encryptedBytes)
        $csDecrypt = [Security.Cryptography.CryptoStream]::new($msDecrypt, $decryptor, [Security.Cryptography.CryptoStreamMode]::Read)
        $srDecrypt = [System.IO.StreamReader]::new($csDecrypt)

        return $srDecrypt.ReadToEnd()
    }
    finally {
        if ($null -ne $srDecrypt) { $srDecrypt.Dispose() }
        if ($null -ne $csDecrypt) { $csDecrypt.Dispose() }
        if ($null -ne $msDecrypt) { $msDecrypt.Dispose() }
        if ($null -ne $decryptor) { $decryptor.Dispose() }
        if ($null -ne $aesAlg) { $aesAlg.Dispose() }
        if ($null -ne $password) { $password.Dispose() }
        if ($null -ne $keyBytes) { [Array]::Clear($keyBytes, 0, $keyBytes.Length) }
        if ($null -ne $hmacKeyBytes) { [Array]::Clear($hmacKeyBytes, 0, $hmacKeyBytes.Length) }
    }
}


if ($mode -eq "Encrypt") {
    $encryptedText = Encrypt-String -clearText $text -key $key -DerivationIterations $DerivationIterations
    if($echo) {
        Write-Host "Encrypted Text: $encryptedText"
    }
    else {
        $encryptedText
    }
    
}
elseif ($mode -eq "Decrypt") {
    $decryptedText = Decrypt-CipherText -cipherText $text -key $key -DerivationIterations $DerivationIterations
    if($echo) {
        Write-Host "Decrypted Text: $decryptedText"
    }
    else {
        $decryptedText
    }
}
else {
    Throw "Invalid mode specified. Please use 'Encrypt' or 'Decrypt'."
}

