#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>

// Important: (///)
// Context:   (+++)

// ----------------------------------------------
// Basic string element counter
// ----------------------------------------------
int str_len(char *str) {
    int i = 0;

    while(str[i] != '\0' && str[i] != '\n') {i++;}

    return (i);
}


// ----------------------------------
// Basic string concatenator
// ----------------------------------
void str_cat(char *origin, char *copy) {

    int i = 0;
    int j = 0;

    while(origin[i] != '\0' && origin[i] != '\n') {i++;}

    while(copy[j] != '\0' && copy[j] != '\n') {
        origin[i] = copy[j];
        i++;
        j++;
    }

    origin[i] = '\0';
}

// --------------------------------------------------------------------
// A basic function to copy the contents of a variable.
// --------------------------------------------------------------------
void str_cpy(char *origin, char *copy) {
    int i = 0;

    while(copy[i] != '\0' && copy[i] != '\n') {
        origin[i] = copy[i];
        i++;
    }

    origin[i] = '\0';
}

// ------------------------------------
// it's a simple count leng string.
// ------------------------------------
int str_len(char *str) {

    int i = 0;

    while(str[i] != '\0' && str[i] != '\n') {i++;}

    return i;
}

// ------------------------
// Function encryption.
// ------------------------
void encrypt_text(static char *pwd, const char *message_origin, unsigned char *out_content, size_t message_len) {
    unsigned char key[crypto_secretbox_KEYBYTES];
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];

    unsigned char cifre[message_len + crypto_secretbox_MACBYTES];
    char descifrado[message_len + 1];

    // ++++++++++++++++++++++
    // Proceso de CRIFRADO:
    // ++++++++++++++++++++++
    
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Generamos los valores unicos para el cifrado y descrifrado.
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
     randombytes_buf(salt, sizeof salt);
     randombytes_buf(nonce, sizeof nonce);

     // ++++++++++++++++++++++++++++++++++++++++++++++
     // Convertimos la clave en una llave hash util.
     // ++++++++++++++++++++++++++++++++++++++++++++++
     crypto_pwhash(key,  sizeof key, pwd, str_len(pwd), salt
             crypto_pwhash_OPSLIMIT_INTERACTIVE,
             crypto_pwhash_MEMLIMIT_INTERACTIVE,
             crypto_ALG_DEFAULT);
     // +++++++++++++++++++++++
     // ciframos el mensaje:
     // +++++++++++++++++++++++
     crypto_secretbox_easy(cifrado, (const unsigned char *)message_origin,
             message_len, nonce, key);

     // +++++++++++++++++++++++++++++++
     // Mostramos el mensaje cifrado:
     // +++++++++++++++++++++++++++++++
     printf("Mensaje cifrado[hex]: ");
     for(SIZE_T i = 0; i sizeof cifrado; i++) {printf("%02x", cifrado[i]);}
     printf("\n");


     // +++++++++++++++++++++++++
     // Proceso de descifrado:
     // +++++++++++++++++++++++++

     if (crypto_secretbox_open_easy((unsigned char *)descifrado, cifrado, sizeof cifrado, nonce, pwd ) != 0) {
         printf("[SYSTEM ERROR]: Incorrect password o corrupt data...\n");
         
         sodium_memzero(pwd, sizeof pwd);
         return (1);
     }

     descifrado[message_len] = '\0';
     printf(">> Data: %s\n", descrifrado);

     // ++++++++++++++++++++++++
     // Liberación de memoria:
     // ++++++++++++++++++++++++
     sodium_memzero(pwd, sizeof pwd);
     return (1);
}

// ---------------------------------------------------
// Main prototype execution environment:
// ---------------------------------------------------
int main(void) {

    // +++++++++++++++++++++++++
    // inicilization library:
    // +++++++++++++++++++++++++
    if(sodium_init() < 0) { 
        printf("[SYSTEM ERROR]:The sodium library is missing, which is required to run this app.\n");
        return (1);
    }

    // +++++++++++++++++++++++++++++++
    // File content buffer.
    // +++++++++++++++++++++++++++++++
    FILE *file;
    int size_buffer = 200;

    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // We obtain the username using their local variable
    // getenv and verify that we have indeed obtained it.
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    char *user_pointer_var = getenv("USER");

    printf("\n[SYSTEM SEARCH]: user search in the work environment variable...\n");

    if (user_pointer_var == NULL) {
        user_pointer_var = getenv("LOGNAME");
    }

    else if (user_pointer_var == NULL) {
        perror("[SYSTEM ERROR]: User not detected to complete file search...\n");
        return (1);
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // We created a buffer variable to avoid direct interaction
    // with the machine's environment variable.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    size_t size_username = str_len(user_pointer_var) + 1;

    char *user = (char *)malloc(size_username * sizeof(char));
    user[0] = '\0';

    // +++++++++++++++++++++++++++++++++++++++++++++++++++
    // We create and initialize the route variable
    // with a maximum buffer size for it (size_buffer).
    // +++++++++++++++++++++++++++++++++++++++++++++++++++
    char *route = malloc(size_buffer * sizeof(char));

    if (route == NULL) {
        perror("[ERROR SYSTEM]: Failed to allocated memory in to creation route...\n");
        return (1);
    }

    // +++++++++++++++++++
    // inicialization.
    // +++++++++++++++++++
    route[0] = '\0';

    printf("[SYSTEM DIRECTION]: creating the file save location...\n");

    // +++++++++++++++++++++++++++
    // Construction of the route.
    // +++++++++++++++++++++++++++
    char *home = "/home/\0";
    
    str_cpy(user, user_pointer_var);
    user_pointer_var = NULL;

    char *name_file = "/archivo\0";
    char *ext_file = ".txt\0";

    str_cat(route, home);
    str_cat(route, user);
    str_cat(route, name_file);
    str_cat(route, ext_file);

    // ++++++++++++++++++++++++++++++++++++++++++++++++++
    // We open the file we're going to read after
    // building the path.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++
    file = fopen(route, "r");
    printf("[SYSTEM DIRECTION]: creation of the file in the assembled address...\n");
    name_file[0] = '\0';
    ext_file[0] = '\0';
    home[0] = '\0';
    user[0] = '\0';

    if (file == NULL) {
        perror("[SYSTEM ERROR]: The file could not be read or found using the path...\n");
        printf("[SYSTEM ERROR]: assembled route: %s\n", route);
        
        route[0] = '\0';
        fclose(file);
        return (1);
    }

    printf("\n[CONTENT FILE]:");

    // ++++++++++++++++++++++++++++++++++++++++++++++
    // read and show the content to the archive.
    // ++++++++++++++++++++++++++++++++++++++++++++++
    
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // vamos al final del archivo para leer la cantidad
    // en bytes de su tamaño.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++
    fseek(archivo, 0, SEEK_END);

    int size_buffer_file = ftell(file);

    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Asignación de memoria en el heap sobre la cantidad de caracteres del archivo.
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    char *copy_content_text = (char *)malloc(size_buffer_file + 1);

    if (copy_content_text == NULL) {
        printf("[MEMORY SYSTEM]: Failed to allocated memory in to creation copy to content...\n");
        return (1);
    }

    // +++++++++++++++++++++++++++++++
    // Volver al inicio del archivo.
    // +++++++++++++++++++++++++++++++
    fseek(file, 0, SEEK_SET);

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // leemos todo el archivo y lo copiamos en la variable: copy_content_text
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    fread(copy_content_text, 1, size_buffer_file, file);
    
    copy_content_text[size_buffer_file] = '\0';

    // +++++++++++++++++++++++
    // Encrytation content:
    // +++++++++++++++++++++++

    // +++++++++++++++++++++++++++++++++++++++++
    // Creation to the private key to encrypt.
    // +++++++++++++++++++++++++++++++++++++++++
    char *key = (char *)malloc(size_buffer * sizeof(char));

    // ++++++++++++++++++++++++++++++++++++++++++++++++++
    // Verification to allocate memory from the malloc.
    // ++++++++++++++++++++++++++++++++++++++++++++++++++
    if (key == NULL) {
        perror("[ERROR SYSTEM]: Failed to allocate memory in the key...");
        return (1);
    }

    printf("\n>Introduce your key to encrypt:");

    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Read to the input the user, only to test the encrypt.
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    fgets(key, sizeof(key), stdin);

    encrypt_text(key, copy_content_text);
    
    free(key);
    free(copy_content_text);

    printf("\n[SYSTEM ENCRYPT]: Encrypt to the all content to the file...\n");
    
    fclose(archivo);
    
    free(route);
    free(user);

    printf("[SYSTEM FILE]: close the file to create and memory free from the heap...\n\n");
    return (0);
}
