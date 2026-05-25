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
int desencrypt_text(int argc, char *argv[]){

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
        return (1);
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Extract the header: Read the original Salt and Nonce.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    if (fread(salt, 1, sizeof salt, file) != sizeof salt || fread(nonce, 1, sizeof nonce, file) != sizeof nonce) {

        fprintf(stderr, "[Error]: The file is incomplete or not a valid format.\n");
        fclose(file);
        return (1);
    }


    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Calculate the size of the remaining encrypted data.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++

    long pos_actual = ftell(file);
    fseek(file, 0, SEEK_END);

    long total_size = ftell(file);
    fseek(file, pos_actual, SEEK_SET); 

    size_t cifrado_len = total_size - pos_actual;

    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // The file must have at least the bytes of the authentication tag (MAC).-
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    if (cifrado_len <= crypto_secretbox_MACBYTES) {
        fprintf(stderr, "[Error]: The file does not contain valid encrypted data.\n");
        fclose(file);
        return 1;
    }


    // ++++++++++++++++++++++++++++++++++++++++++++++
    // Allocate dynamic memory for buffers.
    // ++++++++++++++++++++++++++++++++++++++++++++++
    unsigned char *cifrado = malloc(cifrado_len);
    size_t descifrado_len = cifrado_len - crypto_secretbox_MACBYTES;
    char *descifrado = malloc(descifrado_len + 1); 

    if (cifrado == NULL) {
        fprintf(stderr, "[ERROR]: Memory Allocation Error...\n");
        free(descifrado);
        fclose(file);
        return (1);
    }

    if (descifrado == NULL) {
        fprintf(stderr, "[ERROR]: Memory Allocation Error...\n");
        fclose(file);
        free(cifrado);
        return (1);
    }

    // +++++++++++++++++++++++++++++++++++
    //Read the full cipher block
    // +++++++++++++++++++++++++++++++++++
    size_t bytes_read = fread(cifrado, 1, cifrado_len, file);

    if (bytes_read != cifrado_len) {
        fprintf(stderr, "[Error]: Could not read the entire file (%zu of %zu bytes read).\n", bytes_read, cifrado_len);

        fclose(file);
        free(cifrado);
        free(descifrado);

        return (1);
    }
    fclose(file);


    // +++++++++++++++++++++++++++++++++++++++++++++++++
    //Asking the user for the password securely
    // +++++++++++++++++++++++++++++++++++++++++++++++++
    char pwd_2[256];
    printf("Enter the password to decrypt:");

    if (fgets(pwd_2, sizeof(pwd_2), stdin) == NULL) {
        free(cifrado); 
        free(descifrado);
        return (1);
    }


    // +++++++++++++++++++++++++++++++++++++++++++++++++++
    //  Eliminar el salto de línea '\n' que mete fgets.
    // +++++++++++++++++++++++++++++++++++++++++++++++++++
    pwd_2[str_cspn(pwd_2, "\n")] = '\0';


    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Reconstruir la Clave de cifrado usando el Salt que leímos del archivo
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    printf("Deriving key... (wait a minute)\n");

    if (crypto_pwhash(key, sizeof key, pwd_2, str_len(pwd_2), salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
        fprintf(stderr, "[Error]: Could not generate the hash of the key...\n");
        // +++++++++++++++++++++++++
        // Memory Release.
        // +++++++++++++++++++++++++
        sodium_memzero(pwd_2, sizeof pwd_2);
        free(cifrado); 
        free(descifrado);
        return (1);
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // We no longer need the password in plain text, we delete it immediately.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    sodium_memzero(pwd_2, sizeof pwd_2);

    // ++++++++++++++++++++++++++++++++++++++++
    // We decrypt the contents of the file. 
    // ++++++++++++++++++++++++++++++++++++++++
    if (crypto_secretbox_open_easy((unsigned char *)descifrado, cifrado, cifrado_len, nonce, key) != 0) {

        fprintf(stderr, "\n[SYSTEM ERROR]: Incorrect password o corrupt data...\n");
        // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
        // Limpieza y salida inmediata para evitar SegFaults. 
        // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
        sodium_memzero(key, sizeof key);
        free(cifrado); 
        free(descifrado);
        exit(EXIT_FAILURE);
    }


    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Add the null terminator and print the resulting string.
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    descifrado[descifrado_len] = '\0';

    printf("\n---------------------------------------\n");
    printf(">> DECRYPTED FILE:\n");
    printf("-----------------------------------------\n");
    printf("%s\n", descifrado);
    printf("-----------------------------------------\n");

    // ++++++++++++++++++++++++++++++++++++++++++
    // Final Heap Key Cleaning 
    // ++++++++++++++++++++++++++++++++++++++++++
    sodium_memzero(key, sizeof key);
    free(cifrado);
    free(descifrado);

    return (0);

} 

// ------------------------
// Function encryption.
// ------------------------
int encrypt_text(const char *filename, char *pwd, const char *message, size_t message_len) {

    unsigned char key[crypto_secretbox_KEYBYTES];
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];

    // ++++++++++++++++++++++++++++++++++++++++++++++++++
    // We generate the random keys of key and nonce.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++
    randombytes_buf(salt, sizeof salt);
    randombytes_buf(nonce, sizeof nonce);

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Encrypted buffer needs space for authentication tag (MAC). 
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    size_t cifrado_len = message_len + crypto_secretbox_MACBYTES;
    
    unsigned char *cifrado = malloc(cifrado_len);
    if (cifrado == NULL) { return (1); }
   
    // ++++++++++++++++++++++++++++++++++++++++++++
    // We encrypt the contents of the file. 
    // ++++++++++++++++++++++++++++++++++++++++++++
    if (crypto_pwhash(key, sizeof key, pwd, str_len(pwd), salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
        fprintf(stderr, "[Error]: The hash of the key could not be generated.\n");
        return (1);
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Encrypt the message with the symmetric algorithm using the key and the nonce.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    crypto_secretbox_easy(cifrado, (const unsigned char *)message, message_len, nonce, key);

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
        free(cifrado);
        return (1);
    }


    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Escribir la cabecera (Salt + Nonce) y luego los datos cifrados.
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    fwrite(salt, 1, sizeof salt, file);
    fwrite(nonce, 1, sizeof nonce, file);
    fwrite(cifrado, 1, cifrado_len, file);

    printf("\n---------------------------\n");
    printf(" content[hex]: %s", cifrado);
    printf("\n---------------------------\n");

    // ++++++++++++++++++++++++++++++++++
    // Limpieza de seguridad y cierre
    // ++++++++++++++++++++++++++++++++++
    fclose(file);
    sodium_memzero(key, sizeof key);
    free(cifrado);


    printf("[OK] File '%s' encrypted and saved successfully.\n", filename);

    return (0);

}


int main(int argc, char *argv[]) {
    // -------------------------------------------
    // Inicializar Libsodium obligatoriamente.
    // -------------------------------------------
    if (sodium_init() < 0) {
        fprintf(stderr, "[Error]: Libsodium could not be initialized.\n");
        return (1);
    }

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
    const char *filename = "archivo.txt\0";
    char message[256];
    printf("\nEnter the text you want to encrypt: ");

    if (fgets(message, sizeof(message), stdin) == NULL) {
        pwd[0] = '\0';
        message[0] = '\0';
        return (1);
    }

    size_t len_message = str_len(message);

    encrypt_text(filename, pwd, (const char *)message, len_message);
    
    pwd[0] = '\0';
    message[0] = '\0';

    desencrypt_text(argc, argv);

    return (0);
}



