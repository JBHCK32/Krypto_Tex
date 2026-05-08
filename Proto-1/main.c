#include <stdio.h>
#include <stdlib.h>


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

// ---------------------------------------------------
// Main prototype execution environment:
// ---------------------------------------------------
int main(void) {

    // +++++++++++++++++++++++++++++++
    // File content buffer.
    // +++++++++++++++++++++++++++++++
    FILE *archivo;
    int size_buffer = 100;

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
    int size_username = str_len(user_pointer_var) + 1;

    char *user = (char *)malloc(size_username * sizeof(char));
    user[0] = '\0';

    // +++++++++++++++++++++++++++++++++++++++++++++++++++
    // We create and initialize the route variable
    // with a maximum buffer size for it (size_buffer).
    // +++++++++++++++++++++++++++++++++++++++++++++++++++
    char *route = malloc(size_buffer * sizeof(char));
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
    archivo = fopen(route, "r");
    printf("[SYSTEM DIRECTION]: creation of the file in the assembled address...\n");

    if (archivo == NULL) {
        perror("[SYSTEM ERROR]: The file could not be read or found using the path...\n");
        printf("[SYSTEM ERROR]: assembled route: %s\n", route);
        return (1);
    }

    printf("\n[CONTENT FILE]:");

    // ++++++++++++++++++++++++++++++++++++++++++++++
    // Lectura y mostrar al contenido del archivo.
    // ++++++++++++++++++++++++++++++++++++++++++++++
    char buffer_text[100];

    while(fgets(buffer_text, sizeof(buffer_text), archivo)) {
        printf("%s", buffer_text);
    }

    fclose(archivo);
    
    free(route);
    free(user);

    printf("[SYSTEM FILE]: close the file to create...\n\n");
    return (0);
}
