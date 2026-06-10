#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>
#include <unistd.h>

// Important: (---)
// Context:   (+++)

// ---------------------------------------------------------------------------------
// These are variables that I create to be able to do things in a way that 
// "artisanal", in the end it's just to make the program deterministic, 
// to avoid incessant things and to show that the project is totally transparent.
// ---------------------------------------------------------------------------------
size_t str_len(const char *str) {
    size_t i = 0;
    while(str[i] != '\0') { i++; }
    return (i);
}

size_t str_cspn(const char *str1, const char *str2) {
    size_t i = 0;
    while (str1[i] != '\0') {
        if (str1[i] == str2[0]) {
            return i;
        }
        i++;
    }
    return (i);
}

void str_cat(char *origin, char *copy) {

    int i = 0;
    int j = 0;

    while(origin[i] != '\0') {i++;}

    while(copy[j] != '\0') {
        origin[i] = copy[j];
        i++;
        j++;
    }

    origin[i] = '\0';
}


// -----------------------------------------------------------------------------
// This is the general data saving function for encrypted Krypto Tex data.
// It saves the data right after the EOI marker of JPEG images
// to hide them securely.
// -----------------------------------------------------------------------------
void save_data(const unsigned char *data, size_t data_len, const char *filename, const unsigned char *salt, const unsigned char *nonce) {

    // ++++++++++++++++++++++++++++++++++++++++++++++++++
    // Open the file in binary read/write mode.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++
    FILE *file = fopen(filename, "r+b");

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Verify that the file was opened successfully.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    if (file == NULL) {
        fprintf(stderr, "\n[ERROR]: Failed to open the file\n");
        return;
    }

    int byte_anterior = 0;
    long offset_eoi = 0;
    int c;
    bool eoi = false;

    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Scan the entire file until the EOI marker is found.
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    while ((c = fgetc(file)) != EOF) {

        if (byte_anterior == 0xFF && c == 0xD9) {
            eoi = true;
            offset_eoi = ftell(file);
            break;
        }

        byte_anterior = c;
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Verify that the EOI marker exists; otherwise, notify the user of the error.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    if (!eoi) {
        fprintf(stderr, "\n[Error]: Valid EOI marker (0xFFD9) not found; corrupt or invalid file [JPG].\n");
        fclose(file);
        return;
    }

    // +++++++++++++++++++++++++++++++++++++++++++++++++
    // Move to the EOI position within the file.
    // +++++++++++++++++++++++++++++++++++++++++++++++++
    if (fseek(file, offset_eoi, SEEK_SET) != 0) {
        perror("Failed to position file pointer for writing");
        fclose(file);
        return;
    }

    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // And right after the marker, we write the header containing
    // the salt, nonce, and the encrypted payload.
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    fwrite(salt, 1, crypto_pwhash_SALTBYTES, file);
    fwrite(nonce, 1, crypto_secretbox_NONCEBYTES, file);

    size_t bytes_w = fwrite(data, 1, data_len, file);

    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Check that everything was written correctly.
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    if (bytes_w != data_len) {
        fprintf(stderr, "[ERROR]: Only wrote %zu out of %zu bytes.\n", bytes_w, data_len);
        fclose(file);
        return;
    }

    printf("Successful injection! %zu bytes saved after the EOI (Offset: %ld).\n", data_len, offset_eoi);
    fclose(file);
}

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Main encryption function of Krypto Tex.
// Takes the user's content plus the password provided by them,
// encrypts the content in RAM before it touches the hard drive into the metadata
// of .jpg images.
// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
int encryption_text(const char *route_file, char *pwd, const char *message, size_t message_len) {

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Declare important variables for the encryption process
    // and randomness in the cryptographic key.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    unsigned char key[crypto_secretbox_KEYBYTES];
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    
    const char *filename = route_file;

    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Generate random values for the salt and nonce
    // using the libsodium library.
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    randombytes_buf(salt, sizeof salt);
    randombytes_buf(nonce, sizeof nonce);

    size_t encryption_len = message_len + crypto_secretbox_MACBYTES;
    unsigned char *encryption = malloc(encryption_len);

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Verify that memory for the [encryption] variable has been
    // allocated.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    if (encryption == NULL) { 
        sodium_memzero(key, sizeof key);
        sodium_memzero(salt, sizeof salt);
        sodium_memzero(nonce, sizeof nonce);
        fprintf(stderr, "[ERROR]: An error occurred during memory allocation in the encryption phase...\n");

        return (1); 
    }
    
    pwd[str_cspn(pwd, "\n")] = '\0';

    //+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Generate the cryptographic key using the user's password
    // and the salt, and save everything into the [key] variable.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    if (crypto_pwhash(key, sizeof key, pwd, str_len(pwd), salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
        fprintf(stderr, "[Error]: The hash of the key could not be generated.\n");
        sodium_memzero(key, sizeof key);
        sodium_memzero(salt, sizeof salt);
        sodium_memzero(nonce, sizeof nonce);
        free(encryption);
        return 1;
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Encrypt the content with the generated cryptographic key and save
    // the encrypted content into the [encryption] variable.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    crypto_secretbox_easy(encryption, (const unsigned char *)message, message_len, nonce, key);

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Save the salt, nonce, and encrypted data after the EOI terminator
    // of the JPG image metadata.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    save_data(encryption, encryption_len, filename, salt, nonce);

    // ++++++++++++++++++++++++
    // Free the memory
    // ++++++++++++++++++++++++
    sodium_memzero(key, sizeof key);
    sodium_memzero(salt, sizeof salt);
    sodium_memzero(nonce, sizeof nonce);

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Display the encrypted content of the file to the user in hexadecimal format.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    printf("\n---------------------------\n content[hex]: ");
    for (size_t i = 0; i < encryption_len; i++) {
        printf("%02X ", encryption[i]);
    }
    printf("\n---------------------------\n");

    free(encryption);

    printf("[OK] File '%s' encrypted and saved successfully.\n", filename);
    return (0);
}


// ---------------------------------------------------------------------
// Main decryption function for Krypto Tex content.
// Retrieves the content located after the metadata terminator
// of JPEG files and decrypts it to display it to the user.
// ---------------------------------------------------------------------
int decryption_text(const char *filename) {                                 

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Open the file in binary read-only mode.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++
    FILE *file = fopen(filename, "rb"); 

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Verify that the file opened successfully.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    if (file == NULL) {
        fprintf(stderr, "\n[ERROR]: Error opening file due to lack of privileges or non-existent file\n");
        return (1);
    }

    int byte_anterior = 0;
    long offset_eoi = 0;
    int c;
    bool eoi = false;

    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Scan the entire file until the standard EOI terminator is found.
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    while ((c = fgetc(file)) != EOF) {
        if (byte_anterior == 0xFF && c == 0xD9) {
            eoi = true;
            offset_eoi = ftell(file);
            break;
        }
        byte_anterior = c;
    }

    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Verify if the user provided a valid .jpg file.
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    if (!eoi) {
        fprintf(stderr, "\n[Error]: Valid EOI marker (0xFFD9) not found, corrupt or invalid JPG file.\n");
        fclose(file);
        return (1);
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Calculate how many bytes of hidden content exist up to the EOF.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    fseek(file, 0, SEEK_END);

    long offset_eof = ftell(file);
    long total_payload_len = offset_eof - offset_eoi;

    long min_requerido = crypto_pwhash_SALTBYTES + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES;

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Verify that the file contains data to display to the user.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    if (total_payload_len < min_requerido) {
        fprintf(stderr, "[Error]: The file does not contain Krypto Tex metadata.\n");
        fclose(file);
        return (1);
    }

    size_t encryption_len = total_payload_len - crypto_pwhash_SALTBYTES - crypto_secretbox_NONCEBYTES;

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Return to the beginning of the content after the EOI to extract the salt, 
    // the nonce, and the encrypted data.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    fseek(file, offset_eoi, SEEK_SET);

    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    unsigned char key[crypto_secretbox_KEYBYTES]; 

    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Verify the extraction of the salt to create the cryptographic key.
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    if (fread(salt, 1, crypto_pwhash_SALTBYTES, file) != crypto_pwhash_SALTBYTES) {
        fprintf(stderr, "[Error]: Corrupt or truncated data while reading Salt.\n");
        fclose(file);
        return (1);
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Verify the collection of the nonce to complete the cryptographic key.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    if (fread(nonce, 1, crypto_secretbox_NONCEBYTES, file) != crypto_secretbox_NONCEBYTES) {
        fprintf(stderr, "[Error]: Corrupt or truncated data while reading Nonce.\n");
        fclose(file);
        return (1);
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Declare the variables where the encrypted and decrypted content will be stored.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    unsigned char *encryption = malloc(encryption_len);
    size_t decryption_len = encryption_len - crypto_secretbox_MACBYTES;
    char *decryption = malloc(decryption_len + 1); 

    if (encryption == NULL || decryption == NULL) {
        fprintf(stderr, "\n[ERROR]: Memory Allocation Error...\n");
        free(decryption); 
        free(encryption);
        fclose(file);
        return (1);
    }


    size_t bytes_read = fread(encryption, 1, encryption_len, file);

    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Verify that the encrypted content of the file was successfully read.
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    if (bytes_read != encryption_len) {
        fprintf(stderr, "\n[Error]: Could not read the entire cipher block.\n");
        fclose(file);
        free(decryption); 
        free(encryption);
        return (1);
    }

    fclose(file);

    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Retrieve the user's password to decrypt the encrypted content.
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    char pwd_check[256];
    printf("\n[e] > Enter the password to decrypt: ");

    if (fgets(pwd_check, sizeof(pwd_check), stdin) == NULL) {
        free(decryption); 
        free(encryption);
        return (1);
    }

    pwd_check[str_cspn(pwd_check, "\n")] = '\0';

    printf("\nProcessing key... (wait a moment)\n");

    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Create the cryptographic hash using the user's password, salt,
    // and nonce to decrypt the encrypted content.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    if (crypto_pwhash(key, sizeof key, pwd_check, str_len(pwd_check), salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {

        fprintf(stderr, "\n[Error]: Could not generate the hash of the key...\n");
        sodium_memzero(pwd_check, sizeof pwd_check);
        free(decryption); 
        free(encryption);

        return (1);
    }

    // +++++++++++++++++++++++++++++++++++++++++++++++
    // Clear the user's password from memory.
    // +++++++++++++++++++++++++++++++++++++++++++++++
    sodium_memzero(pwd_check, sizeof pwd_check);

    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Move the decrypted content into the variable to display it in the terminal.
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    if (crypto_secretbox_open_easy((unsigned char *)decryption, encryption, encryption_len, nonce, key) != 0) {
        fprintf(stderr, "\n[SYSTEM ERROR]: Incorrect password or corrupt data...\n");
        free(encryption); 
        free(decryption);
        sodium_memzero(key, sizeof key);

        return (1);
    }

    decryption[decryption_len] = '\0';

    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Display the decrypted content of the retrieved data.
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    printf("\e[32m\n---------------------------------------\e[0m\n");
    printf("\e[35m>>\e[0m \e[32mDECRYPTED FILE:\e[0m\n");
    printf("\e[32m-----------------------------------------\e[0m\n");
    printf("%s\n", decryption);
    printf("\e[32m-----------------------------------------\e[0m\n");

    free(encryption); 
    free(decryption);
    sodium_memzero(key, sizeof key);

    return (0);
}



// ----------------------------------------------------------------------
// This automates the process of creating a base .jpg file
// for the user with the name and location specified in the path
// parameter.
// ----------------------------------------------------------------------
int creation_jpg(char *route_file) {

     
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Open the file in binary write mode ("wb")
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    FILE *file = fopen(route_file, "wb");

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Verify that the file opened successfully.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    if (file == NULL) {
        fprintf(stderr, "\n[ERROR]: Error creating the container file due to lack of privileges or non-existent file.\n");
        return (1);
    }

    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // These are the standard template bytes for the automatic 
    // creation of files with jpg extension.
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    const unsigned char MINIMAL_JPEG[] = {
    0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 
    0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43, 
    0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC0, 0x00, 0x0B, 
    0x08, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x11, 0x00, 0xFF, 0xC4, 0x00, 
    0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xC4, 0x00, 0x14, 
    0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xDA, 0x00, 0x08, 
    0x01, 0x01, 0x00, 0x00, 0x3F, 0x00, 0xBF, 0x00, 0xFF, 0xD9
    };

    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Write padding bytes along with the standard JPEG start and end markers.
    // It is the same for JFIF files.
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    const size_t MINIMAL_JPEG_SIZE = sizeof(MINIMAL_JPEG);

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Write the standard bytes of an empty JPEG to have the
    // container ready to store data.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    size_t bytes_escritos = fwrite(MINIMAL_JPEG, 1, MINIMAL_JPEG_SIZE, file);

    if (bytes_escritos != MINIMAL_JPEG_SIZE) {
        fprintf(stderr, "\n[ERROR]: Error writing the image structure.\n");
        fclose(file);
        return (1);
    }

    fclose(file);

    return (0);
}

// -------------------------------------------------------------------------------
// This function is used to search for special characters in the user password.
// -------------------------------------------------------------------------------
bool verification_special_character(char character) {

    int i = 0;

    char sp_char[] = {
    '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', 
    '_', '+', '-', '=', '[', ']', '{', '}', '|', ';', 
    '\'', ':', '"', ',', '.', '/', '<', '>', '?', '\\', '\0'
    };

    while(sp_char[i] != '\0') {
        
        if (character == sp_char[i]) {
            return (true);
        }

        i++;
    }

    return (false);
}

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++
// This verifies that the user's password meets         +
// the minimum security standards:                      +
//                                                      +
// A minimum length of 8 characters;                    +
// Minimum one uppercase letter [65 - 90 in ASCII];     +
// Minimum one lowercase letter [97 - 122 in ASCII];    +
// Minimum one number [48 - 57 in ASCII];               +
// Minimum one special character;                       +
// ++++++++++++++++++++++++++++++++++++++++++++++++++++++
bool secure_password(char *pwd) {

    int i = 0;
    bool lowercase = false;
    bool uppercase = false;
    int pwd_len = 0;
    bool num_case = false;
    bool specialcase = false;


    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // We simply iterate through the password array and use the ASCII code
    // to verify letter by letter that it meets the minimum requirements of a
    // secure password to be able to encrypt the content.
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    while(pwd[i] != '\0' && pwd[i] != '\n') {

        // ++++++++++++
        // Uppercase.
        // ++++++++++++
        if ((int)pwd[i] >= 65 && (int)pwd[i] <= 90) {
            uppercase = true;
        }

        // ++++++++++++
        // Lowercase.
        // ++++++++++++
        if ((int)pwd[i] >= 97 && (int)pwd[i] <= 122) {
            lowercase = true;
        }

        // +++++++++
        // Nums.
        // +++++++++
        if ((int)pwd[i] >= 48 && (int)pwd[i] <= 57) {
            num_case = true;
        }

        // ++++++++++++++++++++++
        // Special Character.
        // ++++++++++++++++++++++
        if (verification_special_character(pwd[i])) {
            specialcase = true;
        }

        pwd_len++;
        i++;
    }

    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Here it verifies that the password is secure; otherwise, it tells the user
    // what is missing from their password to meet the minimum security requirements.
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    if (pwd_len >= 8 && lowercase && uppercase && num_case && specialcase) {
        return (true);
    }

    else if (pwd_len < 8) {
        printf("\n[ERROR]: Your password does not have the required length [Minimum 8 characters]\n");
        return (false);
    }

    else if (!lowercase) {
        printf("\n[ERROR]: Your password does not have lowercase letters [Minimum one lowercase letter required]\n");
        return (false);
    }

    else if (!uppercase) {
        printf("\n[ERROR]: Your password does not have uppercase letters [Minimum one uppercase letter required]\n");
        return (false);
    }

    else if (!num_case) {
        printf("\n[ERROR]: Your password does not have any digits [Minimum one digit required]\n");
        return (false);
    }

    else if (!specialcase) {
        printf("\n[ERROR]: Your password does not have any special characters [Minimum one special character required]\n");
        return (false);
    }

    return (false);
}

// -------------------------------------------------------------------------------------
// This function removes content by communicating with the kernel to erase everything past the
// metadata terminator of JPG files.
// -------------------------------------------------------------------------------------
bool content_removal(char *route_file) {

     // +++++++++++++++++++++++++++++++++++++++++++++++++++
     // Open in binary read/write mode ("rb+")
     // +++++++++++++++++++++++++++++++++++++++++++++++++++
    FILE *file = fopen(route_file, "rb+");

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Safely verify if the file was opened correctly
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    if (file == NULL) {
        fprintf(stderr, "\n[ERROR]: Could not open the file %s for truncation due to lack of privileges or non-existent file.\n", route_file);
        return (false);
    }

    int current_byte;
    int prev_byte = 0;
    long last_eoi_pos = -1;

    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Traverse byte by byte until the JPEG terminator is found.
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    while ((current_byte = fgetc(file)) != EOF) {
        if (prev_byte == 0xFF && current_byte == 0xD9) {
            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            // ftell gives us the current position (just after 0xD9)
            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            last_eoi_pos = ftell(file);
        }
        prev_byte = current_byte;
    }

    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // If no EOI was found, the file is not a valid JPG or is corrupted
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    if (last_eoi_pos == -1) {
        fprintf(stderr, "\n[ERROR]: EOI marker (0xFFD9) not found in the file; invalid or corrupted file.\n");
        fclose(file);
        return (false);
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Get the native operating system File Descriptor (fd)
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    int fd = fileno(file);

    if (fd == -1) {
        fprintf(stderr, "\n[ERROR]: Failed to obtain the file descriptor.\n");
        fclose(file);
        return (false);
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // ftruncate tells the Linux kernel to cut the file exactly 
    // at the EOI bytes. Everything after it disappears from the hard drive.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    if (ftruncate(fd, last_eoi_pos) != 0) {
        fprintf(stderr, "[ERROR]: Could not apply physical truncation to the file system.\n");
        fclose(file);
        return (false);
    }

    fclose(file);

    return (true);

}

int main(int argc, char *argv[]) {

    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Verify that the shell is currently available.
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    if (system(NULL) == 0) {
        fprintf(stderr, "[X] Error: The command processor (shell) is not available.\n");
        return (1);
    }

    const size_t max_range_message = 10000;

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Execute this command to check if the .kryptotex directory exists;
    // otherwise, create it manually.
    // The program runs strictly with sudo.
    //
    // [INTENTIONAL DESIGN]: Execute environment setup via a static, hardcoded shell command.
    // Because the command string is immutable and accepts zero user input, injection risks are 
    // completely eliminated. This tool strictly mandates root execution for privilege isolation.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    int ret = system("sudo ls -d /root/.kryptotex || sudo mkdir /root/.kryptotex");

    if (ret == -1) {
        fprintf(stderr, "[X] Critical error trying to invoke system()");
        return(1);
    }
    //  ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Verify the exit code of the recently executed command.
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    if (WIFEXITED(ret) && WEXITSTATUS(ret) != 0) {
        fprintf(stderr, "\n[ERROR]: The command terminated with a failure code or lack of privileges: %d\n", WEXITSTATUS(ret));
        return (1);
    }

    
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Verify that the user has the libsodium library.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    if (sodium_init() == -1) {
        fprintf(stderr, "\n[CRITICAL]: Could not initialize libsodium.\n");
        return (1);
    }

    const size_t max_range_route_file = 256;

    

    
        printf("\n\n");
        printf("\e[35m██\e[0m\e[32m╗\e[0m  \e[35m██\e[0m\e[32m╗\e[0m\e[35m██████\e[0m\e[32m╗\e[0m \e[35m██\e[0m\e[32m╗\e[0m   \e[35m██\e[0m\e[32m╗\e[0m\e[35m██████\e[0m\e[32m╗ \e[35m████████\e[0m\e[32m╗\e[35m ██████\e[0m\e[32m╗ \e[0m    \e[35m████████\e[0m\e[32m╗\e[0m\e[35m███████\e[0m\e[32m╗\e[0m\e[35m██\e[0m\e[32m╗ \e[0m \e[35m██\e[0m\e[32m╗\e[0m\n");
        printf("\e[35m██\e[32m║ \e[35m██\e[32m╔╝\e[35m██\e[32m╔══\e[35m██\e[32m╗╚\e[0m\e[35m██\e[32m╗ \e[35m██\e[32m╔╝\e[35m██\e[32m╔══\e[35m██\e[32m╗╚══\e[0m\e[35m██\e[32m╔══╝\e[35m██\e[32m╔═══\e[35m██\e[32m╗\e[0m    \e[32m╚══\e[35m██\e[32m╔══╝\e[35m██\e[32m╔════╝╚\e[0m\e[35m██\e[32m╗\e[35m██\e[32m╔╝\e[0m\n");
        printf("\e[35m█████\e[32m╔╝ \e[35m██████\e[32m╔╝ \e[32m╚\e[35m████\e[32m╔╝ \e[35m██████\e[32m╔╝   \e[35m██\e[32m║   \e[35m██\e[32m║   \e[35m██\e[32m║\e[0m       \e[35m██\e[32m║   \e[35m█████\e[32m╗   \e[32m╚\e[35m███\e[32m╔╝ \e[0m\n");
        printf("\e[35m██\e[32m╔═\e[35m██\e[32m╗ \e[35m██\e[32m╔══\e[35m██\e[32m╗  \e[32m╚\e[35m██\e[32m╔╝  \e[35m██\e[32m╔═══╝    \e[35m██\e[32m║   \e[35m██\e[32m║   \e[35m██\e[32m║\e[0m       \e[35m██\e[32m║   \e[35m██\e[32m╔══╝   \e[35m██\e[32m╔\e[35m██\e[32m╗ \e[0m\n");
        printf("\e[35m██\e[32m║  \e[35m██\e[32m╗\e[35m██\e[32m║  \e[35m██\e[32m║   \e[35m██\e[32m║   \e[35m██\e[32m║        \e[35m██\e[32m║   \e[32m╚\e[35m██████\e[32m╔╝\e[0m       \e[35m██\e[32m║   \e[35m███████\e[32m╗\e[35m██\e[32m╔╝ \e[35m██\e[32m╗\e[0m\n");
        printf("\e[32m╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝ \e[0m       \e[32m╚═╝   ╚══════╝╚═╝  ╚═╝\e[0m\n");
        printf("\n\n");
        printf("\e[32m ── [ DATA CLOAKING SYSTEM by James] ─────────────────────────────────────── v0.1.0 ──\e[0m\n");
        printf("\e[32m-------------------------------------------------------------------------------------------\e[0m\n");
        printf("\e[35m[>]\e[0m \e[32mStatus: PRE-LIMINAR (Active Steneography mode))\e[0m\n");
        printf("\e[35m[>]\e[0m \e[32mTarget: Custom User File via CLI\e[0m\n");
        printf("\e[32m-------------------------------------------------------------------------------------------\e[0m\n");
        printf("\e[35m1.\e[0m \e[32mOpen File(jpg)\e[0m\n");
        printf("\e[35m2.\e[0m \e[32mCreate a new file(jpg)\e[0m\n");
        printf("\e[35m3.\e[0m \e[32mEdit File(jpg)\e[0m\n");

        char op[4];
        printf("\n\n\e[35m[\e[32m->\e[0m\e[35m]Option:\e[0m");

        // +++++++++++++++++++++++++++++++++++++++++++++++++++
        // Get user input with fgets
        // to choose the option they want to execute.
        // +++++++++++++++++++++++++++++++++++++++++++++++++++
        if (fgets(op, sizeof(op), stdin) == NULL) {
            op[0] = '\0';
            return (1);
        }
        

        // ++++++++++++++++++++++++++++++++++++++++++++++++
        // Option to view file content.
        // ++++++++++++++++++++++++++++++++++++++++++++++++
        if (op[0] == '1' ) {

            op[0] = '\0';

            // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            // Verify that the user has provided the path of the file they want to view.
            // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            if (argc < 2) {
                fprintf(stderr, "[!] A path is required to view file content: %s /path/to/file.jpg", argv[0]);
                return (1);
            }

            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            // Verify that the argument path respects the buffer limits.
            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            if (str_len(argv[1]) >= max_range_route_file) {
                fprintf(stderr, "\n[ERROR]: The file path you entered is too large for the expected size.\n");
                return (1);
            }

            char route_new_file[max_range_route_file];
            route_new_file[0] = '\0';

            str_cat(route_new_file, argv[1]);

            // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            // Activate the decryption process with the user's path.
            // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            int res_decrypt = decryption_text(route_new_file);

            if (res_decrypt == 1) {
                fprintf(stderr, "\n[ERROR]: A problem occurred during file decryption...\n");
            }

            // +++++++++++++++++++++++++
            // Free memory.
            // +++++++++++++++++++++++++
            sodium_memzero(route_new_file, sizeof route_new_file);
            sodium_memzero(op, sizeof op);
        }

        // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
        // Option for the user to create a new file.
        // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
        else if (op[0] == '2') {

            op[0] = '\0';

            const size_t max_range_filename = 100;

            // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            // Receive the name of the file the user wants to create.
            // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            char filename[max_range_filename];
            printf("\n[>] Enter the name of the file you are going to create: ");

            if (fgets(filename, sizeof(filename), stdin) == NULL) {
                sodium_memzero(filename, sizeof filename);
                return (1);
            }

            filename[str_cspn(filename, "\n")] = '\0';

            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            // Get the default path of the new file created by the user.
            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            char route_new_file[118] = "/root/.kryptotex/";
        
            str_cat(route_new_file, filename);

            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            // Create the jpg file in the default secure path.
            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            creation_jpg(route_new_file);

            sodium_memzero(filename, sizeof filename); 

            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++
            // Process of adding new content for the user:
            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++ 
            
            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            // Securely get the new content with fgets.
            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            char message[max_range_message];
            printf("\n\e[32m+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\e[32m\n");
            printf(" \e[32m[Manual]: to stop writing and send the message all at once to be encrypted you need to use the [Ctrl + D]\n \e[0m");
            printf("\e[32m key combination to stop writing and encrypt everything.\e[0m\n\n");

            printf("\e[35m [Warning]: If the content you enter exceeds the character limit which is %ld\n\e[0m", max_range_message);
            printf("\e[35m then the program will ignore them and only write what is within that range.\e[0m");
            printf("\n\e[32m+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\e[0m\n");

            printf(" \n[+] Enter the content you want inside the file: \n");     

            size_t current_len = 0;
            char line[1024];

            // ---------------------------------------------------------------------------
            // While verifies the completion of the user's content with the EOF but 
            // stops if the estimated buffer for the user's message is exceeded.
            //
            // This allows the user to write with line breaks and gives the user 
            // the option to send the input with a combination of Ctrl + D.
            // ---------------------------------------------------------------------------
            while (current_len < (max_range_message - 1)) {
                if (fgets(line, sizeof(line), stdin) == NULL) break;

                // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
                // The idea is to read line by line of what the user writes. 
                // We copy the line into the buffer
                // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
                size_t line_len = 0;
                line_len = str_len(line); 

                // ++++++++++++++++++++++++++++++++++++++++++++++++
                // We verify that what the user typed does not 
                // exceed the buffer that was limited.
                // ++++++++++++++++++++++++++++++++++++++++++++++++
                if (current_len + line_len > (max_range_message - 1)) {
                    
                    line[0] = '\0';
                    message[0] = '\0';
                    clearerr(stdin);
 
                    printf("\n\n[Critic Error]: Message limit reached: [%ld characters].\n", max_range_message);

                    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
                    // Here we send a specific code of a buffer overflow, it is 
                    // not a normal error but a special code that tells us what happened.
                    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
                    return (101);
                }
 
                // ++++++++++++++++++++++++++++++++++++++++++++
                // Otherwise, we copy line by line what the 
                // user has written in the buffer message.
                // ++++++++++++++++++++++++++++++++++++++++++++
                for(size_t j = 0; j < line_len; j++) {
                    message[current_len++] = line[j];
                }

            }

            // ++++++++++++++++++++++++++++++++++++
            // We put the obligatory finalizer
            // ++++++++++++++++++++++++++++++++++++
            message[current_len] = '\0';

            // +++++++++++++++++++++++++++++++++++++++++++++
            // We close the stdin entry of the program.
            // +++++++++++++++++++++++++++++++++++++++++++++
            if (feof(stdin)) {
                clearerr(stdin);
            } 

            // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            // We reactivate the stdin entry in the active terminal that the user is using,
            // but simply the program dies since we do not have access to the user's input.
            // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            if (freopen("/dev/tty", "r", stdin) == NULL) {
                fprintf(stderr, "\n\n[ERROR]: the stdin could not be reopened, there was a problem in the process of reopening the user's input, ending the program...\n\n");
                return (1);
            }

            const size_t max_range_pwd = 256;

            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            // Securely get user input with fgets to obtain the user's password.
            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            char pwd[max_range_pwd];
            printf("\e[35m\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\e[0m\n");
            printf("\e[35m[\e[0m\e[32mWARNING\e[30m\e[35m]\e[0m\e[32m: This application does not store or recover passwords. \e[0m");
            printf("\e[32m\nThe key you enter exists only in volatile memory and is purged immediately after use.\e[0m");
            printf("\e[32m\nIf you lose this password, your encrypted data will be permanently inaccessible.\e[0m");
            printf("\e[35m\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\e[0m\n");

            printf("[>] Now enter a secure password for your file: ");

            if (fgets(pwd, sizeof(pwd), stdin) == NULL) {
                sodium_memzero(pwd, sizeof pwd);
                sodium_memzero(message, sizeof message);
                printf("\n\n[ERROR]: A problem occurred in the password stdin\n\n");
                return (1);
            }

            pwd[str_cspn(pwd, "\n")] = '\0';


            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            // Verify the security of the user's password;
            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            bool secure_pwd = secure_password(pwd);

            if (!secure_pwd) {
                fprintf(stderr, "\n[ERROR]: Your password did not meet the minimum security requirements to encrypt the content.\n");
                sodium_memzero(pwd, sizeof pwd);
                sodium_memzero(message, sizeof message); 
            
                return (1);
            }


            int message_len = str_len(message);

            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            // Pass everything to the encryption function and verify that everything
            // went well.
            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            int res_encrypt = encryption_text(route_new_file, pwd, message, message_len);

            sodium_memzero(pwd, sizeof pwd);
            sodium_memzero(message, sizeof message);
            sodium_memzero(route_new_file, sizeof route_new_file);
            message_len = 0;


            if (res_encrypt != 0) {
                fprintf(stderr, "\n[ERROR]: An error occurred during the encryption process.\n");
                return (1);
            }

            message[0] = '\0';
            pwd[0] = '\0';
            filename[0] = '\0';

        }

        // +++++++++++++++++++++++++
        // Option to edit a file.
        // +++++++++++++++++++++++++
        else if (op[0] == '3') {

            op[0] = '\0';

            // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            // Verify that the user has provided a valid path to execute the function.
            // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            if (argc < 2) {
                fprintf(stderr, "[!] A path is required to edit a file: %s /path/to/file.jpg", argv[0]);
                return (1);
            }

            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            // Verify that the argument path respects the buffer limits.
            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            if (str_len(argv[1]) >= max_range_route_file) {
                fprintf(stderr, "\n[ERROR]: The file path you entered is too large for the expected size.\n");
                return (1);
            }

            // ++++++++++++++++++++++++++++++
            // Inicialization variables.
            // +++++++++++++++++++++++++++++++
            char route_new_file[max_range_route_file];
            
            route_new_file[0] = '\0';

            str_cat(route_new_file, argv[1]);

            
            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            // Process of removing previous file content an verification
            // that the process is executed correctly.
            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            if (!content_removal(route_new_file)) {
                fprintf(stderr, "\n[ERROR]: There was an error in the truncation process because the file was non-existent or\n"); 
                fprintf(stderr, "\nyou didn't have the necessary permissions (or simply an error of the truncation function).\n");
                return (1);
            }

            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++
            // Process of adding new content for the user:
            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++ 
            
            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            // Securely get the new content with fgets.
            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            char message[max_range_message];
            printf("\n\e[32m+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\e[32m\n");
            printf(" \e[32m[Manual]: to stop writing and send the message all at once to be encrypted you need to use the [Ctrl + D]\n \e[0m");
            printf("\e[32m key combination to stop writing and encrypt everything.\e[0m\n\n");

            printf("\e[35m [Warning]: If the content you enter exceeds the character limit which is %ld\n\e[0m", max_range_message);
            printf("\e[35m then the program will ignore them and only write what is within that range.\e[0m");
            printf("\n\e[32m+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\e[0m\n");


            printf(" \n[+] Enter the content you want inside the file: \n");

            size_t current_len = 0;
            char line[1024];

            // ---------------------------------------------------------------------------
            // While verifies the completion of the user's content with the EOF but 
            // stops if the estimated buffer for the user's message is exceeded.
            //
            // This allows the user to write with line breaks and gives the user 
            // the option to send the input with a combination of Ctrl + D.
            // ---------------------------------------------------------------------------
            while (current_len < (max_range_message - 1)) {
                if (fgets(line, sizeof(line), stdin) == NULL) break;

                // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
                // The idea is to read line by line of what the user writes. 
                // We copy the line into the buffer
                // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
                size_t line_len = 0;
                line_len = str_len(line); 

                // ++++++++++++++++++++++++++++++++++++++++++++++++
                // We verify that what the user typed does not 
                // exceed the buffer that was limited.
                // ++++++++++++++++++++++++++++++++++++++++++++++++
                if (current_len + line_len > (max_range_message - 1)) {
                    line[0] = '\0';
                    message[0] = '\0';
                    clearerr(stdin);
 
                    printf("\n\n[Critic Error]: Message limit reached: [%ld characters].\n", max_range_message);

                    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
                    // Here we send a specific code of a buffer overflow, it is 
                    // not a normal error but a special code that tells us what happened.
                    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
                    return (101);
                }
 
                // ++++++++++++++++++++++++++++++++++++++++++++
                // Otherwise, we copy line by line what the 
                // user has written in the buffer message.
                // ++++++++++++++++++++++++++++++++++++++++++++
                for(size_t j = 0; j < line_len; j++) {
                    message[current_len++] = line[j];
                }

            }

            // ++++++++++++++++++++++++++++++++++++
            // We put the obligatory finalizer
            // ++++++++++++++++++++++++++++++++++++
            message[current_len] = '\0';

            // +++++++++++++++++++++++++++++++++++++++++++++
            // We close the stdin entry of the program.
            // +++++++++++++++++++++++++++++++++++++++++++++
            if (feof(stdin)) {
                clearerr(stdin);
            } 

            // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            // We reactivate the stdin entry in the active terminal that the user is using,
            // but simply the program dies since we do not have access to the user's input.
            // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            if (freopen("/dev/tty", "r", stdin) == NULL) {
                fprintf(stderr, "\n\n[ERROR]: the stdin could not be reopened, there was a problem in the process of reopening the user's input, ending the program...\n\n");
                return (1);
            }


            const size_t max_range_pwd = 256;

            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++
            // Securely get the password with fgets.
            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++
            char pwd[max_range_pwd];
            printf("\e[35m\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\e[0m\n");
            printf("\e[35m[\e[0m\e[32mWARNING\e[30m\e[35m]\e[0m\e[32m: This application does not store or recover passwords. \e[0m");
            printf("\e[32m\nThe key you enter exists only in volatile memory and is purged immediately after use.\e[0m");
            printf("\e[32m\nIf you lose this password, your encrypted data will be permanently inaccessible.\e[0m");
            printf("\e[35m\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\e[0m\n");

            printf("[>] Now enter a secure password for your file: ");

            if (fgets(pwd, sizeof(pwd), stdin) == NULL) {
                sodium_memzero(pwd, sizeof pwd);
                sodium_memzero(message, sizeof message);

                return (1);
            }

            pwd[str_cspn(pwd, "\n")] = '\0'; // This is done to remove the trailing newline character left by fgets.


            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            // Verify the security of the user's password;
            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            bool secure_pwd = secure_password(pwd);

            if (!secure_pwd) {
                fprintf(stderr, "\n[ERROR]: Your password did not meet the minimum security requirements to encrypt the content.\n");
                sodium_memzero(pwd, sizeof pwd);
                sodium_memzero(message, sizeof message);
                
                return (1);
            }


    
           
            int message_len = str_len(message);

            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            // And pass everything to the user content encryption function.
            // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            int res_encrypt = encryption_text(route_new_file, pwd, message, message_len);
            
            sodium_memzero(pwd, sizeof pwd);
            sodium_memzero(message, sizeof message);
            sodium_memzero(route_new_file, sizeof route_new_file);
            message_len = 0;
    


            if (res_encrypt != 0) {
                fprintf(stderr, "\n[ERROR]: An error occurred during the encryption process.\n");
                return (1);
            }
        }


    return (0);
}
