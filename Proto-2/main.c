#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>

// Important: (---)
// Context:   (+++)

// ---------------------------------------------------------------
// It's a function I wrote that looks for a character inside a 
// string and returns the position of the string.
// ---------------------------------------------------------------
size_t str_cspn(const char *str1, const char *str2) {
    
    int i = 0;

    while (str1[i] != '\0') {

        if (str1[i] == str2[0]) {
            return (i);
        }

        i++;
    }

    return (i);
}

// ---------------------------------------------------------------------------
// A function that counts the number of characters in a list of characters.
// ---------------------------------------------------------------------------
int str_len(const char *str) {
    int i = 0;

    while(str[i] != '\0' && str[i] != '\n') {i++;}

    return (i);
}

// -------------------------------------------------------------------------------------
// This function decrypts with the parameters that the user enters as the name of 
// the file to be decrypted and the program will ask for the password to be able 
// to view the content of the encrypted file.
// -------------------------------------------------------------------------------------
int decryption_text(int argc, char *argv[]){

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Validate that the user passes the file name by argument
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    if (argc < 2) {
        fprintf(stderr, "Uso: %s <nombre_del_archivo_cifrado>\n", argv[0]);
        return (1);
    }


    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Declaration of variables: name of the file, the key which is the symmetric secret key, salt is 
    // what differs from each password, it prevents brute force attacks if you do not have the salt, the nonce 
    // is so that the files look different every time they are encrypted.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    const char *filename = argv[1];
    unsigned char key[crypto_secretbox_KEYBYTES];
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];


    // +++++++++++++++++++++++++++++++++++++++++++++++
    // Open the file in binary read mode ("rb").
    // +++++++++++++++++++++++++++++++++++++++++++++++
    FILE *file = fopen(filename, "rb");

    if (filename == NULL || filename[0] == '\0') {
        fprintf(stderr, "[ERROR]: Invalid or null name file...\n");

        sodium_memzero(key, sizeof key);
        sodium_memzero(nonce, sizeof nonce);
        sodium_memzero(salt, sizeof salt);

        return (1);
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Extract the header: Read the original Salt and Nonce.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    if (fread(salt, 1, sizeof salt, file) != sizeof salt || fread(nonce, 1, sizeof nonce, file) != sizeof nonce) {

        fprintf(stderr, "[Error]: The file is incomplete or not a valid format.\n");
        fclose(file);

        sodium_memzero(key, sizeof key);
        sodium_memzero(nonce, sizeof nonce);
        sodium_memzero(salt, sizeof salt);

        return (1);
    }


    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Calculate the size of the remaining encrypted data.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++

    long pos_actual = ftell(file);
    fseek(file, 0, SEEK_END);

    long total_size = ftell(file);
    fseek(file, pos_actual, SEEK_SET); 

    size_t encryption_len = total_size - pos_actual;

    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // The file must have at least the bytes of the authentication tag (MAC).-
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    if (encryption_len <= crypto_secretbox_MACBYTES) {
        fprintf(stderr, "[Error]: The file does not contain valid encrypted data.\n");
        
        fclose(file);
        
        sodium_memzero(key, sizeof key);
        sodium_memzero(nonce, sizeof nonce);
        sodium_memzero(salt, sizeof salt);

        encryption_len = 0;

        return (1);
    }


    // ++++++++++++++++++++++++++++++++++++++++++++++
    // Allocate dynamic memory for buffers.
    // ++++++++++++++++++++++++++++++++++++++++++++++
    unsigned char *encryption = malloc(encryption_len);
    size_t decryption_len = encryption_len - crypto_secretbox_MACBYTES;
    char *decryption = malloc(decryption_len + 1); 

    if (encryption == NULL || decryption == NULL) {
        fprintf(stderr, "[ERROR]: Memory Allocation Error...\n");

        free(decryption); 
        free(encryption);

        sodium_memzero(key, sizeof key);
        sodium_memzero(nonce, sizeof nonce);
        sodium_memzero(salt, sizeof salt);

        fclose(file);

        return (1);
    }

    // +++++++++++++++++++++++++++++++++++
    // Read the full cipher block
    // +++++++++++++++++++++++++++++++++++
    size_t bytes_read = fread(encryption, 1, encryption_len, file);

    if (bytes_read != encryption_len) {
        fprintf(stderr, "[Error]: Could not read the entire file (%zu of %zu bytes read).\n", bytes_read, encryption_len);

        fclose(file);
        free(decryption); 
        free(encryption);

        sodium_memzero(key, sizeof key);
        sodium_memzero(nonce, sizeof nonce);
        sodium_memzero(salt, sizeof salt);

        return (1);
    }

    fclose(file);


    // +++++++++++++++++++++++++++++++++++++++++++++++++
    // Asking the user for the password securely
    // +++++++++++++++++++++++++++++++++++++++++++++++++
    char pwd_check[256];
    printf("[e] > Enter the password to decrypt:");

    if (fgets(pwd_check, sizeof(pwd_check), stdin) == NULL) {
        free(decryption); 
        free(encryption);

        sodium_memzero(key, sizeof key);
        sodium_memzero(nonce, sizeof nonce);
        sodium_memzero(salt, sizeof salt);

        pwd_check[0] = '\0';

        return (1);
    }


    // +++++++++++++++++++++++++++++++++++++++++++++++++++
    // Remove the line break '\n' that puts fgets in.  
    // +++++++++++++++++++++++++++++++++++++++++++++++++++
    pwd_check[str_cspn(pwd_check, "\n")] = '\0';


    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Reconstruct the encryption key using the Salt we read from the file. 
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    printf("Processing key... (wait a minute)\n");

    if (crypto_pwhash(key, sizeof key, pwd_check, str_len(pwd_check), salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {

        fprintf(stderr, "[Error]: Could not generate the hash of the key...\n");
        // +++++++++++++++++++++++++
        // Memory Release.
        // +++++++++++++++++++++++++
        sodium_memzero(pwd_check, sizeof pwd_check);
        free(decryption); 
        free(encryption);

        sodium_memzero(key, sizeof key);
        sodium_memzero(nonce, sizeof nonce);
        sodium_memzero(salt, sizeof salt);

        pwd_check[0] = '\0';

        return (1);
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // We no longer need the password in plain text, we delete it immediately.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    sodium_memzero(pwd_check, sizeof pwd_check);

    // ++++++++++++++++++++++++++++++++++++++++
    // We decrypt the contents of the file. 
    // ++++++++++++++++++++++++++++++++++++++++
    if (crypto_secretbox_open_easy((unsigned char *)decryption, encryption, encryption_len, nonce, key) != 0) {

        fprintf(stderr, "\n[SYSTEM ERROR]: Incorrect password o corrupt data...\n");
        // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
        // Limpieza y salida inmediata para evitar SegFaults. 
        // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
        free(encryption); 
        free(decryption);

        sodium_memzero(key, sizeof key);
        sodium_memzero(nonce, sizeof nonce);
        sodium_memzero(salt, sizeof salt);

        pwd_check[0] = '\0';

        return (1);
    }

    pwd_check[0] = '\0';


    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Add the null terminator and print the resulting string.
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    decryption[decryption_len] = '\0';

    printf("\n---------------------------------------\n");
    printf(">> DECRYPTED FILE:\n");
    printf("-----------------------------------------\n");
    printf("%s\n", decryption);
    printf("-----------------------------------------\n");

    // ++++++++++++++++++++++++++++++++++++++++++
    // Final Heap Key Cleaning 
    // ++++++++++++++++++++++++++++++++++++++++++
    free(encryption); 
    free(decryption);

    sodium_memzero(key, sizeof key);
    sodium_memzero(nonce, sizeof nonce);
    sodium_memzero(salt, sizeof salt);

    return (0);

} 

// ------------------------
// Function encryption.
// ------------------------
int encrypt_text(char *argv[], char *pwd, const char *message, size_t message_len) {

    unsigned char key[crypto_secretbox_KEYBYTES];
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];

    const char *filename = argv[1];

    // ++++++++++++++++++++++++++++++++++++++++++++++++++
    // We generate the random keys of key and nonce.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++
    randombytes_buf(salt, sizeof salt);
    randombytes_buf(nonce, sizeof nonce);

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Encrypted buffer needs space for authentication tag (MAC). 
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    size_t encryption_len = message_len + crypto_secretbox_MACBYTES;
    
    unsigned char *encryption = malloc(encryption_len);

    if (encryption == NULL) { 
        encryption_len = 0;
        
        sodium_memzero(key, sizeof key);
        sodium_memzero(salt, sizeof salt);
        sodium_memzero(nonce, sizeof nonce);

        return (1); 
    }

    pwd[str_cspn(pwd, "\n")] = '\0';

    // ++++++++++++++++++++++++++++++++++++++++++++
    // We encrypt the contents of the file. 
    // ++++++++++++++++++++++++++++++++++++++++++++
    if (crypto_pwhash(key, sizeof key, pwd, str_len(pwd), salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
        fprintf(stderr, "[Error]: The hash of the key could not be generated.\n");
        
        sodium_memzero(key, sizeof key);
        sodium_memzero(salt, sizeof salt);
        sodium_memzero(nonce, sizeof nonce);
        
        return (1);
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Encrypt the message with the symmetric algorithm using the key and the nonce.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    crypto_secretbox_easy(encryption, (const unsigned char *)message, message_len, nonce, key);

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Open file to write in binary mode ("wb").
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++  
    FILE *file = fopen(filename, "wb");

    if (file == NULL) {
        perror("[ERROR]: Error opening file to write...\n");
        // ++++++++++++++++++++++++++++++++++++
        // Memory release and cleaning.
        // ++++++++++++++++++++++++++++++++++++
        sodium_memzero(key, sizeof key);
        sodium_memzero(salt, sizeof salt);
        sodium_memzero(nonce, sizeof nonce);

        free(encryption);
        return (1);
    }


    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Type the header (Salt + Nonce) and then the encrypted data. 
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    fwrite(salt, 1, sizeof salt, file);
    fwrite(nonce, 1, sizeof nonce, file);
    fwrite(encryption, 1, encryption_len, file);


    printf("\n---------------------------\n content[hex]: ");
    for (size_t i = 0; i < encryption_len; i++) {
        printf("%02X ", encryption[i]);
    }
    printf("\n---------------------------\n");


    // ++++++++++++++++++++++++++++++++++
    // Safety cleaning and shut-off. 
    // ++++++++++++++++++++++++++++++++++
    fclose(file);

    sodium_memzero(key, sizeof key);
    sodium_memzero(salt, sizeof salt);
    sodium_memzero(nonce, sizeof nonce);

    free(encryption);
    


    printf("[OK] File '%s' encrypted and saved successfully.\n", filename);

    return (0);

}


int main(int argc, char *argv[]) {
    // -------------------------------------------
    // Libsodium Initializator is mandatory. 
    // -------------------------------------------
    if (sodium_init() < 0) {
        fprintf(stderr, "[Error]: Libsodium could not be initialized.\n");
        return (1);
    }

    printf("\n\n");
    printf("\e[35m██\e[0m\e[32m╗\e[0m  \e[35m██\e[0m\e[32m╗\e[0m\e[35m██████\e[0m\e[32m╗\e[0m \e[35m██\e[0m\e[32m╗\e[0m   \e[35m██\e[0m\e[32m╗\e[0m\e[35m██████\e[0m\e[32m╗ \e[35m████████\e[0m\e[32m╗\e[35m ██████\e[0m\e[32m╗ \e[0m    \e[35m████████\e[0m\e[32m╗\e[0m\e[35m███████\e[0m\e[32m╗\e[0m\e[35m██\e[0m\e[32m╗ \e[0m \e[35m██\e[0m\e[32m╗\e[0m\n");
    printf("\e[35m██\e[32m║ \e[35m██\e[32m╔╝\e[35m██\e[32m╔══\e[35m██\e[32m╗╚\e[0m\e[35m██\e[32m╗ \e[35m██\e[32m╔╝\e[35m██\e[32m╔══\e[35m██\e[32m╗╚══\e[0m\e[35m██\e[32m╔══╝\e[35m██\e[32m╔═══\e[35m██\e[32m╗\e[0m    \e[32m╚══\e[35m██\e[32m╔══╝\e[35m██\e[32m╔════╝╚\e[0m\e[35m██\e[32m╗\e[35m██\e[32m╔╝\e[0m\n");
    printf("\e[35m█████\e[32m╔╝ \e[35m██████\e[32m╔╝ \e[32m╚\e[35m████\e[32m╔╝ \e[35m██████\e[32m╔╝   \e[35m██\e[32m║   \e[35m██\e[32m║   \e[35m██\e[32m║\e[0m       \e[35m██\e[32m║   \e[35m█████\e[32m╗   \e[32m╚\e[35m███\e[32m╔╝ \e[0m\n");
    printf("\e[35m██\e[32m╔═\e[35m██\e[32m╗ \e[35m██\e[32m╔══\e[35m██\e[32m╗  \e[32m╚\e[35m██\e[32m╔╝  \e[35m██\e[32m╔═══╝    \e[35m██\e[32m║   \e[35m██\e[32m║   \e[35m██\e[32m║\e[0m       \e[35m██\e[32m║   \e[35m██\e[32m╔══╝   \e[35m██\e[32m╔\e[35m██\e[32m╗ \e[0m\n");
    printf("\e[35m██\e[32m║  \e[35m██\e[32m╗\e[35m██\e[32m║  \e[35m██\e[32m║   \e[35m██\e[32m║   \e[35m██\e[32m║        \e[35m██\e[32m║   \e[32m╚\e[35m██████\e[32m╔╝\e[0m       \e[35m██\e[32m║   \e[35m███████\e[32m╗\e[35m██\e[32m╔╝ \e[35m██\e[32m╗\e[0m\n");
    printf("\e[32m╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝ \e[0m       \e[32m╚═╝   ╚══════╝╚═╝  ╚═╝\e[0m\n");
    printf("\n\n");
    printf(" ── [ DATA CLOAKING SYSTEM by James] ─────────────────────────────────────── v0.0.1 ──\n");
    printf("-------------------------------------------------------------------------------------------\n");
    printf("[>] Status: PRE-LIMINAR (Active Encryption Mode))\n");
    printf("[>] Target: Custom User File via CLI\n");
    printf("-------------------------------------------------------------------------------------------\n");

    char pwd[256];
    printf("Enter the password to encrypt:");

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // We use fgets to get input from the user with their password and use it 
    // to encrypt files.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    if (fgets(pwd, sizeof(pwd), stdin) == NULL) {
        pwd[0] = '\0';
        return (1);
    }

    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Remove the line break '\n' that puts fgets in input.  +
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++
    pwd[str_cspn(pwd, "\n")] = '\0';

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Default data to test the prototype quickly.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++
    char message[256];
    printf("\nEnter the text you want to encrypt: ");

    if (fgets(message, sizeof(message), stdin) == NULL) {

        pwd[0] = '\0';
        message[0] = '\0';

        return (1);
    }

    size_t len_message = str_len(message);

    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // We encrypt user information, release and empty variables used, decryption content
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    if (encrypt_text(argv, pwd, (const char *)message, len_message) == 1) {
        fprintf(stderr, "[ERROR]: An error occurred in the encryption process...\n");
        pwd[0] = '\0';
        message[0] = '\0';
        len_message = 0;

        return (1);
    }
    
    pwd[0] = '\0';
    message[0] = '\0';
    len_message = 0;

    if (decryption_text(argc, argv) == 1) {
        fprintf(stderr, "[ERROR]: An error occurred in the decryption process...\n");

        pwd[0] = '\0';
        message[0] = '\0';
        len_message = 0;

        return (1);
    }

    return (0);
}



