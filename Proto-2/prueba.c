#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>


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

int str_len(const char *str) {
    int i = 0;

    while(str[i] != '\0' && str[i] != '\n') {i++;}

    return (i);
}

int desencrypt_text(int argc, char *argv[]){

    // Validar que el usuario pase el nombre del archivo por argumento
    if (argc < 2) {
        fprintf(stderr, "Uso: %s <nombre_del_archivo_cifrado>\n", argv[0]);
        return (1);
    }


    const char *filename = argv[1];
    unsigned char key[crypto_secretbox_KEYBYTES];
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];


    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Abrir el archivo en modo lectura binaria ("rb")
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++
    FILE *file = fopen(filename, "rb");


    if (file == NULL) {
        perror("[ERROR]: Error al abrir el archivo...\n");
        return (1);
    }


    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Extraer la cabecera: Leer el Salt y el Nonce originales
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

    if (fread(salt, 1, sizeof salt, file) != sizeof salt || fread(nonce, 1, sizeof nonce, file) != sizeof nonce) {

        fprintf(stderr, "Error: El archivo está incompleto o no es un formato válido.\n");
        fclose(file);
        return (1);
    }


    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Calcular el tamaño de los datos cifrados restantes
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++

    long pos_actual = ftell(file);
    fseek(file, 0, SEEK_END);

    long total_size = ftell(file);
    fseek(file, pos_actual, SEEK_SET); 

    size_t cifrado_len = total_size - pos_actual;

    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // El archivo debe tener al menos los bytes del tag de autenticación (MAC)
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

    if (cifrado_len <= crypto_secretbox_MACBYTES) {

        fprintf(stderr, "Error: El archivo no contiene datos cifrados válidos.\n");
        fclose(file);
        return 1;
    }


    // ++++++++++++++++++++++++++++++++++++++++++++++
    // Asignar memoria dinámica para los búferes
    // ++++++++++++++++++++++++++++++++++++++++++++++
    unsigned char *cifrado = malloc(cifrado_len);
    size_t descifrado_len = cifrado_len - crypto_secretbox_MACBYTES;
    char *descifrado = malloc(descifrado_len + 1); 

    if (cifrado == NULL) {
        fprintf(stderr, "[ERROR]: error de asiganción de memoria...\n");
        free(descifrado);
        fclose(file);
        return (1);
    }

    if (descifrado == NULL) {
        fprintf(stderr, "Error de asignación de memoria.\n");
        fclose(file);
        free(cifrado);
        return (1);
    }

    // +++++++++++++++++++++++++++++++++++
    // Leer el bloque cifrado completo
    // +++++++++++++++++++++++++++++++++++
    fread(cifrado, 1, cifrado_len, file);
    fclose(file);


    // +++++++++++++++++++++++++++++++++++++++++++++++++
    // Pedir la contraseña al usuario de forma segura
    char pwd_2[256];
    printf("Introduce la contraseña para descifrar: ");

    if (fgets(pwd_2, sizeof(pwd_2), stdin) == NULL) {
        free(cifrado); 
        free(descifrado);
        return (1);
    }


    // +++++++++++++++++++++++++++++++++++++++++++++++++++
    // Eliminar el salto de línea '\n' que mete fgets
    // +++++++++++++++++++++++++++++++++++++++++++++++++++
    pwd_2[str_cspn(pwd_2, "\n")] = '\0';


    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Reconstruir la Clave de cifrado usando el Salt que leímos del archivo
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    printf("Derivando clave... (espera un momento)\n");

    if (crypto_pwhash(key, sizeof key, pwd_2, str_len(pwd_2), salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
        fprintf(stderr, "[Error]: No se pudo generar el hash de la clave...\n");
        // +++++++++++++++++++++++++
        // Liberación de memoria.
        // +++++++++++++++++++++++++
        sodium_memzero(pwd_2, sizeof pwd_2);
        free(cifrado); 
        free(descifrado);
        return (1);
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Ya no necesitamos la contraseña en texto plano, la borramos de inmediato
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    sodium_memzero(pwd_2, sizeof pwd_2);

    // ++++++++++++++++++++++++++++++++++++++++
    // Desciframos el contenido del archivo.
    // ++++++++++++++++++++++++++++++++++++++++
    if (crypto_secretbox_open_easy((unsigned char *)descifrado, cifrado, cifrado_len, nonce, key) != 0) {

        fprintf(stderr, "\n[SYSTEM ERROR]: Incorrect password o corrupt data...\n");
        // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
        // Freno de mano: Limpieza y salida inmediata para evitar SegFaults
        // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
        sodium_memzero(key, sizeof key);
        free(cifrado); 
        free(descifrado);
        exit(EXIT_FAILURE);
    }


    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Agregar el terminador nulo e imprimir el string resultante
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    descifrado[descifrado_len] = '\0';

    printf("\n---------------------------------------\n");
    printf(">> ARCHIVO DESCIFRADO:\n");
    printf("-----------------------------------------\n");
    printf("%s\n", descifrado);
    printf("-----------------------------------------\n");

    // ++++++++++++++++++++++++++++++++++++++++++
    // Limpieza final de la clave del heap
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
    // Generamos las llaves aleatorias de key y nonce
    // ++++++++++++++++++++++++++++++++++++++++++++++++++
    randombytes_buf(salt, sizeof salt);
    randombytes_buf(nonce, sizeof nonce);

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // El búfer cifrado necesita espacio para el tag de autenticación (MAC)
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    size_t cifrado_len = message_len + crypto_secretbox_MACBYTES;
    
    unsigned char *cifrado = malloc(cifrado_len);
    if (cifrado == NULL) { return (1); }
   
    // ++++++++++++++++++++++++++++++++++++++++++++
    // Encryptamos el contenido del archivo.
    // ++++++++++++++++++++++++++++++++++++++++++++
    if (crypto_pwhash(key, sizeof key, pwd, str_len(pwd), salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
        fprintf(stderr, "Error: No se pudo generar el hash de la clave.\n");
        return (1);
    }


    // 3. Cifrar el mensaje con el algoritmo simétrico usando la clave y el nonce
    crypto_secretbox_easy(cifrado, (const unsigned char *)message, message_len, nonce, key);

    // 4. Abrir archivo para escribir en modo binario ("wb")
    FILE *file = fopen(filename, "wb");

    if (file == NULL) {
        perror("Error al abrir el archivo para escribir");
        // ++++++++++++++++++++++++++++++++++++
        // Liberación de memoria y limpieza.
        // ++++++++++++++++++++++++++++++++++++
        sodium_memzero(key, sizeof key);
        free(cifrado);
        return (1);
    }


    // 5. Escribir la cabecera (Salt + Nonce) y luego los datos cifrados
    fwrite(salt, 1, sizeof salt, file);
    fwrite(nonce, 1, sizeof nonce, file);
    fwrite(cifrado, 1, cifrado_len, file);

    printf("\n---------------------------\n");
    printf("contenido[hex]: %s", cifrado);
    printf("\n---------------------------\n");

    // ++++++++++++++++++++++++++++++++++
    // Limpieza de seguridad y cierre
    // ++++++++++++++++++++++++++++++++++
    fclose(file);
    sodium_memzero(key, sizeof key);
    free(cifrado);


    printf("[OK] Archivo '%s' cifrado y guardado con éxito.\n", filename);

    return (0);

}


int main(int argc, char *argv[]) {
    // -------------------------------------------
    // Inicializar Libsodium obligatoriamente.
    // -------------------------------------------
    if (sodium_init() < 0) {
        fprintf(stderr, "Error: No se pudo inicializar libsodium.\n");
        return (1);
    }

    char pwd[256];
    printf("Introduce la contraseña para cifrar:");

    if (fgets(pwd, sizeof(pwd), stdin) == NULL) {
        pwd[0] = '\0';
        return (1);
    }

    // +++++++++++++++++++++++++++++++++++++++++++++++++++
    // Eliminar el salto de línea '\n' que mete fgets
    // +++++++++++++++++++++++++++++++++++++++++++++++++++
    pwd[str_cspn(pwd, "\n")] = '\0';


    const char *filename = "archivo.txt\0";
    char message[256];
    printf("\nIntroduce el texto que quieres cifrar:");

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

    return (1);
}



