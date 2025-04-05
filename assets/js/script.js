// Caesar Cipher Implementation (shift by 3)
function caesarEncrypt(plaintext, shift) {
    let result = '';
    for (let i = 0; i < plaintext.length; i++) {
        let char = plaintext.charAt(i);
        if (char.match(/[a-z]/i)) {
            let charCode = plaintext.charCodeAt(i);
            let shiftCode = (charCode >= 65 && charCode <= 90)
                ? 65
                : 97; // ASCII value for 'A' or 'a'
            result += String.fromCharCode(((charCode - shiftCode + shift) % 26) + shiftCode);
        } else {
            result += char;
        }
    }
    return result;
}

function caesarDecrypt(ciphertext, shift) {
    return caesarEncrypt(ciphertext, 26 - shift);  // Reverse the shift for decryption
}

// Vigenère Cipher Implementation
function vigenereEncrypt(plaintext, key) {
    let result = '';
    let j = 0;
    for (let i = 0; i < plaintext.length; i++) {
        let char = plaintext.charAt(i);
        if (char.match(/[a-zA-Z]/)) {
            const keyChar = key.charAt(j % key.length).toLowerCase();
            const shift = keyChar.charCodeAt(0) - 97;  // 'a' = 97, 'b' = 98, ...
            let charCode = char.charCodeAt(0);

            if (char.match(/[a-z]/)) {
                result += String.fromCharCode(((charCode - 97 + shift) % 26) + 97);
            } else {
                result += String.fromCharCode(((charCode - 65 + shift) % 26) + 65);
            }
            j++;
        } else {
            result += char;  // Non-alphabetical characters are added unchanged
        }
    }
    return result;
}

function vigenereDecrypt(ciphertext, key) {
    let result = '';
    let j = 0;
    for (let i = 0; i < ciphertext.length; i++) {
        let char = ciphertext.charAt(i);
        if (char.match(/[a-zA-Z]/)) {
            const keyChar = key.charAt(j % key.length).toLowerCase();
            const shift = keyChar.charCodeAt(0) - 97;  // 'a' = 97, 'b' = 98, ...
            let charCode = char.charCodeAt(0);

            if (char.match(/[a-z]/)) {
                result += String.fromCharCode(((charCode - 97 - shift + 26) % 26) + 97);
            } else {
                result += String.fromCharCode(((charCode - 65 - shift + 26) % 26) + 65);
            }
            j++;
        } else {
            result += char;  // Non-alphabetical characters are added unchanged
        }
    }
    return result;
}


// Atbash Cipher Implementation
function atbashEncryptDecrypt(text) {
    const alphabet = 'abcdefghijklmnopqrstuvwxyz';
    let result = '';
    for (let i = 0; i < text.length; i++) {
        let char = text.charAt(i).toLowerCase();
        if (alphabet.indexOf(char) !== -1) {
            const index = alphabet.indexOf(char);
            result += alphabet[25 - index];
        } else {
            result += text.charAt(i);
        }
    }
    return result;
}

// Rail-Fence Cipher Implementation
function railFenceEncrypt(text, numRails) {
    let rails = Array(numRails).fill('').map(() => []);
    let direction = 1;
    let railIndex = 0;

    for (let i = 0; i < text.length; i++) {
        rails[railIndex].push(text.charAt(i));
        railIndex += direction;
        if (railIndex === 0 || railIndex === numRails - 1) {
            direction = -direction;
        }
    }

    return rails.map(rail => rail.join('')).join('');
}

function railFenceDecrypt(text, numRails) {
    let result = Array(text.length).fill('');
    let direction = 1;
    let railIndex = 0;
    let pos = 0;

    // Create the pattern of rails
    for (let i = 0; i < text.length; i++) {
        result[railIndex] = '*';
        railIndex += direction;
        if (railIndex === 0 || railIndex === numRails - 1) {
            direction = -direction;
        }
    }

    railIndex = 0;
    direction = 1;

    // Fill in the result with characters from the encrypted text
    for (let i = 0; i < text.length; i++) {
        if (result[railIndex] === '*') {
            result[railIndex] = text.charAt(pos++);
        }
        railIndex += direction;
        if (railIndex === 0 || railIndex === numRails - 1) {
            direction = -direction;
        }
    }

    return result.join('');
}

// Playfair Cipher Implementation
function playfairEncrypt(plaintext, key) {
    const matrix = generatePlayfairMatrix(key);
    let result = '';
    plaintext = plaintext.toLowerCase().replace(/j/g, 'i');
    // Ensure the text is of even length by adding 'x' if necessary
    if (plaintext.length % 2 !== 0) {
        plaintext += 'x';
    }

    for (let i = 0; i < plaintext.length; i += 2) {
        let a = plaintext[i];
        let b = plaintext[i + 1];

        let aPos = findPosition(matrix, a);
        let bPos = findPosition(matrix, b);

        if (aPos.row === bPos.row) {
            result += matrix[aPos.row][(aPos.col + 1) % 5];
            result += matrix[bPos.row][(bPos.col + 1) % 5];
        } else if (aPos.col === bPos.col) {
            result += matrix[(aPos.row + 1) % 5][aPos.col];
            result += matrix[(bPos.row + 1) % 5][bPos.col];
        } else {
            result += matrix[aPos.row][bPos.col];
            result += matrix[bPos.row][aPos.col];
        }
    }

    return result;
}

function playfairDecrypt(ciphertext, key) {
    const matrix = generatePlayfairMatrix(key);
    let result = '';
    ciphertext = ciphertext.toLowerCase().replace(/j/g, 'i');

    for (let i = 0; i < ciphertext.length; i += 2) {
        let a = ciphertext[i];
        let b = ciphertext[i + 1];

        let aPos = findPosition(matrix, a);
        let bPos = findPosition(matrix, b);

        if (aPos.row === bPos.row) {
            result += matrix[aPos.row][(aPos.col - 1 + 5) % 5];
            result += matrix[bPos.row][(bPos.col - 1 + 5) % 5];
        } else if (aPos.col === bPos.col) {
            result += matrix[(aPos.row - 1 + 5) % 5][aPos.col];
            result += matrix[(bPos.row - 1 + 5) % 5][bPos.col];
        } else {
            result += matrix[aPos.row][bPos.col];
            result += matrix[bPos.row][aPos.col];
        }
    }

    return result;
}

function generatePlayfairMatrix(key) {
    const alphabet = 'abcdefghiklmnopqrstuvwxyz'; // 'j' is omitted
    let matrix = [];
    key = key.toLowerCase().replace(/[^a-z]/g, '').replace(/j/g, 'i');

    // Remove duplicates from key
    key = key.split('').filter((value, index, self) => self.indexOf(value) === index).join('');

    let used = key.split('');
    let alphabetArr = alphabet.split('');

    for (let char of alphabetArr) {
        if (!used.includes(char)) {
            used.push(char);
        }
    }

    // Create a 5x5 matrix
    for (let i = 0; i < 5; i++) {
        matrix.push(used.slice(i * 5, (i + 1) * 5));
    }

    return matrix;
}

function findPosition(matrix, char) {
    for (let i = 0; i < matrix.length; i++) {
        for (let j = 0; j < matrix[i].length; j++) {
            if (matrix[i][j] === char) {
                return { row: i, col: j };
            }
        }
    }
    return null;
}

// Affine Cipher Implementation
function affineEncrypt(text, a, b) {
    let result = '';
    for (let i = 0; i < text.length; i++) {
        let char = text.charAt(i);
        if (char.match(/[a-zA-Z]/)) {
            let charCode = char.charCodeAt(0);
            let base = char.match(/[a-z]/) ? 97 : 65;
            result += String.fromCharCode(((a * (charCode - base) + b) % 26) + base);
        } else {
            result += char;
        }
    }
    return result;
}

function affineDecrypt(text, a, b) {
    const aInverse = modInverse(a, 26); // Find modular inverse of 'a' modulo 26
    let result = '';
    for (let i = 0; i < text.length; i++) {
        let char = text.charAt(i);
        if (char.match(/[a-zA-Z]/)) {
            let charCode = char.charCodeAt(0);
            let base = char.match(/[a-z]/) ? 97 : 65;
            result += String.fromCharCode((aInverse * (charCode - base - b + 26)) % 26 + base);
        } else {
            result += char;
        }
    }
    return result;
}

// Modular Inverse Function
function modInverse(a, m) {
    for (let i = 1; i < m; i++) {
        if ((a * i) % m === 1) {
            return i;
        }
    }
    return -1; // No modular inverse if no such number exists
}

// Base64 Encoding/Decoding
function base64Encode(text) {
    return btoa(text); // Base64 encode
}

function base64Decode(encodedText) {
    return atob(encodedText); // Base64 decode
}

// Base32 Encoding/Decoding
function base32Encode(text) {
    return btoa(text).replace(/=/g, ''); // Simple Base32 (no padding)
}

function base32Decode(encodedText) {
    return atob(encodedText + '=='); // Base32 decode
}

// Base58 Encoding/Decoding (simplified version)
function base58Encode(text) {
    const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    let result = '';
    let num = parseInt(text, 10);
    while (num > 0) {
        result = alphabet[num % 58] + result;
        num = Math.floor(num / 58);
    }
    return result;
}

function base58Decode(encodedText) {
    const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    let num = 0;
    for (let i = 0; i < encodedText.length; i++) {
        num = num * 58 + alphabet.indexOf(encodedText.charAt(i));
    }
    return num.toString();
}

// Fungsi untuk menampilkan atau menyembunyikan input kata kunci
document.getElementById('algorithm').addEventListener('change', function() {
    const algorithm = this.value;
    const keyInputContainer = document.getElementById('key-input-container');
    
    // Tampilkan input kata kunci hanya untuk algoritma yang memerlukannya
    if (algorithm === 'vigenere' || algorithm === 'affine' || algorithm === 'playfair') {
        keyInputContainer.classList.remove('hidden');
    } else {
        keyInputContainer.classList.add('hidden');
    }
});

// Event listeners for encryption and decryption
document.getElementById('encrypt-btn').addEventListener('click', () => {
    const text = document.getElementById('input-text').value;
    const algorithm = document.getElementById('algorithm').value;
    const key = document.getElementById('key-input').value;
    let result;

    if (algorithm === 'caesar') {
        const shift = 3;
        result = caesarEncrypt(text, shift);
    } else if (algorithm === 'vigenere') {
        if (!key) {
            alert("Please enter a key for Vigenère Cipher.");
            return;
        }
        result = vigenereEncrypt(text, key);
    } else if (algorithm === 'atbash') {
        result = atbashEncryptDecrypt(text);
    } else if (algorithm === 'rail-fence') {
        const rails = 3;
        result = railFenceEncrypt(text, rails);
    } else if (algorithm === 'playfair') {
        result = playfairEncrypt(text, key);
    } else if (algorithm === 'affine') {
        const a = 5;
        const b = 8;
        result = affineEncrypt(text, a, b);
    } else if (algorithm === 'base64') {
        result = base64Encode(text);
    } else if (algorithm === 'base32') {
        result = base32Encode(text);
    } else if (algorithm === 'base58') {
        result = base58Encode(text);
    }

    document.getElementById('output-text').value = result;
});

document.getElementById('decrypt-btn').addEventListener('click', () => {
    const text = document.getElementById('input-text').value;
    const algorithm = document.getElementById('algorithm').value;
    const key = document.getElementById('key-input').value;
    let result;

    if (algorithm === 'caesar') {
        const shift = 3;
        result = caesarDecrypt(text, shift);
    } else if (algorithm === 'vigenere') {
        if (!key) {
            alert("Please enter a key for Vigenère Cipher.");
            return;
        }
        result = vigenereDecrypt(text, key);
    } else if (algorithm === 'atbash') {
        result = atbashEncryptDecrypt(text);
    } else if (algorithm === 'rail-fence') {
        const rails = 3;
        result = railFenceDecrypt(text, rails);
    } else if (algorithm === 'playfair') {
        result = playfairDecrypt(text, key);
    } else if (algorithm === 'affine') {
        const a = 5;
        const b = 8;
        result = affineDecrypt(text, a, b);
    } else if (algorithm === 'base64') {
        result = base64Decode(text);
    } else if (algorithm === 'base32') {
        result = base32Decode(text);
    } else if (algorithm === 'base58') {
        result = base58Decode(text);
    }

    document.getElementById('output-text').value = result;
});
