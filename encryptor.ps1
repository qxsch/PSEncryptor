param(
    [Parameter(Position=0,mandatory=$true, ValueFromPipeline=$true)]
    [string]$text,
    
    [Parameter(Position=1,mandatory=$false)]
    [string]$key="MySecretKey",


    [Parameter(Position=2,mandatory=$false)]
    [ValidateSet("Encrypt","Decrypt")]
    [string]$mode="Encrypt",

    [switch]$echo
)

function Encrypt-String {
    param (
        [string]$clearText,
        [string]$key
    )

    # Constants for encryption
    $KeySize = 128
    $DerivationIterations = 1000

    # Generate random bytes for salt and initialization vector (IV)
    $saltStringBytes = New-Object byte[] 16
    $ivStringBytes = New-Object byte[] 16
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
        [string]$key
    )

    # Constants for decryption
    $KeySize = 128
    $DerivationIterations = 1000

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
    $encryptedText = Encrypt-String -clearText $text -key $key
    if($echo) {
        Write-Host "Encrypted Text: $encryptedText"
    }
    else {
        $encryptedText
    }
    
}
elseif ($mode -eq "Decrypt") {
    $decryptedText = Decrypt-CipherText -cipherText $text -key $key
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

