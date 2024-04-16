<#
.SYNOPSIS
Encrypts or decrypts a string using AES encryption.

.DESCRIPTION
This scripts encrypts or decrypts a string using AES encryption. It generates random bytes for salt and initialization vector (IV) using PBKDF2.

.PARAMETER text
The text to be encrypted. Can also be used to pipe text to the script.

.PARAMETER key
The key to be used for encryption. If not provided, a default key "MySecretKey" is used.

.PARAMETER mode
Should it encrypt or decrypt the provided text. Default is Encrypt. Use Decrypt to decrypt the text.

.PARAMETER echo
This switch is used to write the output to the console.

.OUTPUTS
The encrypted or decrypted text. If the -echo switch is used, the output is written to the console.

.EXAMPLE
./encryptor.ps1 -text "Hello, World!" -key "mysecret"
This example encrypts the string "Hello, World!" using the key "mysecret".

.EXAMPLE
.\encryptor.ps1 "vTrVExZplQJfV6PCt4++L1MDlHUMjAyhhZMV77PsAjzoy8lojIEx9LfGKjK1akxm" -key "mysecret" -mode Decrypt
This example decrypts the string back to "Hello, World!" using the key "mysecret".

.NOTES
The key size is set to 128 (AES-128).
#>


param(
    [Parameter(Position=0,mandatory=$true, ValueFromPipeline=$true)]
    [string]$text,
    
    [Parameter(Position=1,mandatory=$false)]
    [string]$key="MySecretKey",


    [Parameter(Position=2,mandatory=$false)]
    [ValidateSet("Encrypt","Decrypt")]
    [string]$mode="Encrypt",

    [int32]$DerivationIterations = 1000,

    [switch]$echo
)

if($DerivationIterations -lt 10) {
    Throw "DerivationIterations cannot be below 10."
}
if($DerivationIterations -gt 2100000000) {
    Throw "DerivationIterations cannot be above 2'100'000'000."
}

function Encrypt-String {
    param (
        [string]$clearText,
        [string]$key,
        [int32]$DerivationIterations = 1000
    )

    # Constants for encryption
    $KeySize = 128

    # Generate random bytes for salt and initialization vector (IV)
    $saltStringBytes = New-Object byte[] ($KeySize / 8)
    $ivStringBytes = New-Object byte[] ($KeySize / 8)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($saltStringBytes)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($ivStringBytes)

    # Derive a key from the password and salt using PBKDF2
    $password = [Security.Cryptography.Rfc2898DeriveBytes]::new($key, $saltStringBytes, $DerivationIterations, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $keyBytes = $password.GetBytes($KeySize / 8)

    # Create an AES encryption algorithm
    $symmetricKey = [System.Security.Cryptography.Aes]::Create()

    # Create an encryptor
    $encryptor = $symmetricKey.CreateEncryptor($keyBytes, $ivStringBytes)

    # Create memory streams for encryption
    $memoryStream = [System.IO.MemoryStream]::new()
    $cryptoStream = [System.Security.Cryptography.CryptoStream]::new($memoryStream, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
    $streamWriter = [System.IO.StreamWriter]::new($cryptoStream)
    $streamWriter.Write($clearText)
    $streamWriter.Close()

    # Combine salt, IV, and encrypted data into the final cipher text
    $cipherTextBytes = $saltStringBytes + $ivStringBytes + $memoryStream.ToArray()

    # Convert the combined data (salt, IV, and encrypted data) to a Base64-encoded string
    return [Convert]::ToBase64String($cipherTextBytes)
}

function Decrypt-CipherText {
    param (
        [string]$cipherText,
        [string]$key,
        [int32]$DerivationIterations = 1000
    )

    # Constants for decryption
    $KeySize = 128

    # Convert the base64-encoded cipher text to bytes
    $cipherTextBytesWithSaltAndIv = [Convert]::FromBase64String($cipherText)

    # Extract the salt and IV (Initialization Vector) from the cipher text
    $saltStringBytes = $cipherTextBytesWithSaltAndIv[0..(($KeySize / 8) - 1)]
    $ivStringBytes = $cipherTextBytesWithSaltAndIv[($KeySize / 8)..(($KeySize / 8 * 2) - 1)]

    # Derive the encryption key from the provided key and salt
    $password = [Security.Cryptography.Rfc2898DeriveBytes]::new($key, $saltStringBytes, $DerivationIterations, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $keyBytes = $password.GetBytes($KeySize / 8)

    # Create an AES cipher with the derived key
    $aesAlg = [Security.Cryptography.Aes]::Create()

    # Create a decryptor with the key and IV
    $decryptor = $aesAlg.CreateDecryptor($keyBytes, $ivStringBytes)

    # Decrypt the cipher text
    $originalCipherText = $cipherTextBytesWithSaltAndIv[($KeySize / 8 * 2)..($cipherTextBytesWithSaltAndIv.Length - 1)]

    # Create a memory stream to hold the original cipher text
    $msDecrypt = [System.IO.MemoryStream]::new($originalCipherText)

    # Create a crypto stream to perform decryption
    $csDecrypt = [Security.Cryptography.CryptoStream]::new($msDecrypt, $decryptor, [Security.Cryptography.CryptoStreamMode]::Read)

    # Create a stream reader to read the decrypted data
    $srDecrypt = [System.IO.StreamReader]::new($csDecrypt)

    # Return the decrypted plain text
    return $srDecrypt.ReadToEnd()
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

