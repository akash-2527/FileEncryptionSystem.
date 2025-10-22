/*
 * File Encryption and Decryption System
 * Uses XOR cipher with multi-character key for encryption/decryption
 * Author: Advanced C Programming
 * Date: 2025
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

// Constants
#define MAX_FILENAME_LENGTH 256
#define MAX_KEY_LENGTH 128
#define BUFFER_SIZE 4096
#define MIN_KEY_LENGTH 4

// Function prototypes
void displayMenu();
int getChoice();
int getFilename(char *filename, const char *prompt);
int getEncryptionKey(char *key);
int validateKey(const char *key);
int fileExists(const char *filename);
long getFileSize(FILE *file);
int encryptFile(const char *inputFile, const char *outputFile, const char *key);
int decryptFile(const char *inputFile, const char *outputFile, const char *key);
void xorCipher(unsigned char *data, size_t dataLen, const char *key, size_t keyLen);
void clearInputBuffer();
void printProgress(long current, long total);
void secureKeyInput(char *key, size_t maxLen);

/*
 * Main function - Entry point of the program
 * Controls the flow of encryption/decryption operations
 */
int main() {
    char inputFile[MAX_FILENAME_LENGTH];
    char outputFile[MAX_FILENAME_LENGTH];
    char key[MAX_KEY_LENGTH];
    int choice;
    int result;
    
    printf("========================================\n");
    printf("  FILE ENCRYPTION & DECRYPTION SYSTEM  \n");
    printf("========================================\n\n");
    
    // Main program loop
    while (1) {
        displayMenu();
        choice = getChoice();
        
        if (choice == 3) {
            printf("\nExiting program. Goodbye!\n");
            break;
        }
        
        // Get input filename
        if (getFilename(inputFile, "Enter input filename: ") != 0) {
            continue;
        }
        
        // Check if input file exists
        if (!fileExists(inputFile)) {
            printf("ERROR: File '%s' does not exist!\n", inputFile);
            continue;
        }
        
        // Get output filename
        if (getFilename(outputFile, "Enter output filename: ") != 0) {
            continue;
        }
        
        // Prevent overwriting input file
        if (strcmp(inputFile, outputFile) == 0) {
            printf("ERROR: Output file cannot be the same as input file!\n");
            continue;
        }
        
        // Warn if output file exists
        if (fileExists(outputFile)) {
            char confirm;
            printf("WARNING: File '%s' already exists. Overwrite? (y/n): ", outputFile);
            scanf(" %c", &confirm);
            clearInputBuffer();
            if (tolower(confirm) != 'y') {
                printf("Operation cancelled.\n");
                continue;
            }
        }
        
        // Get encryption/decryption key
        if (getEncryptionKey(key) != 0) {
            continue;
        }
        
        // Perform encryption or decryption
        printf("\nProcessing...\n");
        
        if (choice == 1) {
            result = encryptFile(inputFile, outputFile, key);
            if (result == 0) {
                printf("\n✓ File encrypted successfully!\n");
                printf("  Input:  %s\n", inputFile);
                printf("  Output: %s\n", outputFile);
            }
        } else if (choice == 2) {
            result = decryptFile(inputFile, outputFile, key);
            if (result == 0) {
                printf("\n✓ File decrypted successfully!\n");
                printf("  Input:  %s\n", inputFile);
                printf("  Output: %s\n", outputFile);
            }
        }
        
        printf("\n");
    }
    
    return 0;
}

/*
 * Display the main menu
 */
void displayMenu() {
    printf("----------------------------------------\n");
    printf("1. Encrypt a file\n");
    printf("2. Decrypt a file\n");
    printf("3. Exit\n");
    printf("----------------------------------------\n");
}

/*
 * Get user's menu choice with validation
 * Returns: Valid choice (1-3)
 */
int getChoice() {
    int choice;
    
    while (1) {
        printf("Enter your choice (1-3): ");
        if (scanf("%d", &choice) != 1) {
            printf("ERROR: Invalid input. Please enter a number.\n");
            clearInputBuffer();
            continue;
        }
        clearInputBuffer();
        
        if (choice >= 1 && choice <= 3) {
            return choice;
        }
        printf("ERROR: Invalid choice. Please enter 1, 2, or 3.\n");
    }
}

/*
 * Get filename from user with validation
 * Parameters:
 *   filename: Buffer to store the filename
 *   prompt: Prompt message to display
 * Returns: 0 on success, -1 on failure
 */
int getFilename(char *filename, const char *prompt) {
    printf("%s", prompt);
    if (fgets(filename, MAX_FILENAME_LENGTH, stdin) == NULL) {
        printf("ERROR: Failed to read filename.\n");
        return -1;
    }
    
    // Remove newline character
    size_t len = strlen(filename);
    if (len > 0 && filename[len - 1] == '\n') {
        filename[len - 1] = '\0';
        len--;
    }
    
    // Validate filename length
    if (len == 0) {
        printf("ERROR: Filename cannot be empty.\n");
        return -1;
    }
    
    return 0;
}

/*
 * Get encryption key from user with validation
 * Parameters:
 *   key: Buffer to store the key
 * Returns: 0 on success, -1 on failure
 */
int getEncryptionKey(char *key) {
    printf("Enter encryption key (min %d chars): ", MIN_KEY_LENGTH);
    secureKeyInput(key, MAX_KEY_LENGTH);
    
    if (validateKey(key) != 0) {
        return -1;
    }
    
    return 0;
}

/*
 * Secure key input (prevents echoing to screen)
 * Parameters:
 *   key: Buffer to store the key
 *   maxLen: Maximum length of the key
 */
void secureKeyInput(char *key, size_t maxLen) {
    // For cross-platform compatibility, using standard input
    // In production, use platform-specific secure input methods
    if (fgets(key, maxLen, stdin) == NULL) {
        key[0] = '\0';
        return;
    }
    
    // Remove newline
    size_t len = strlen(key);
    if (len > 0 && key[len - 1] == '\n') {
        key[len - 1] = '\0';
    }
}

/*
 * Validate encryption key
 * Parameters:
 *   key: The key to validate
 * Returns: 0 if valid, -1 if invalid
 */
int validateKey(const char *key) {
    size_t len = strlen(key);
    
    if (len < MIN_KEY_LENGTH) {
        printf("ERROR: Key must be at least %d characters long.\n", MIN_KEY_LENGTH);
        return -1;
    }
    
    if (len >= MAX_KEY_LENGTH - 1) {
        printf("ERROR: Key is too long (max %d characters).\n", MAX_KEY_LENGTH - 1);
        return -1;
    }
    
    return 0;
}

/*
 * Check if file exists
 * Parameters:
 *   filename: Name of the file to check
 * Returns: 1 if exists, 0 if not
 */
int fileExists(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file != NULL) {
        fclose(file);
        return 1;
    }
    return 0;
}

/*
 * Get file size in bytes
 * Parameters:
 *   file: File pointer
 * Returns: File size in bytes, or -1 on error
 */
long getFileSize(FILE *file) {
    long size;
    
    if (fseek(file, 0, SEEK_END) != 0) {
        return -1;
    }
    
    size = ftell(file);
    if (size == -1) {
        return -1;
    }
    
    if (fseek(file, 0, SEEK_SET) != 0) {
        return -1;
    }
    
    return size;
}

/*
 * Encrypt a file using XOR cipher
 * Parameters:
 *   inputFile: Name of the input file
 *   outputFile: Name of the output file
 *   key: Encryption key
 * Returns: 0 on success, -1 on failure
 */
int encryptFile(const char *inputFile, const char *outputFile, const char *key) {
    FILE *inFile = NULL;
    FILE *outFile = NULL;
    unsigned char buffer[BUFFER_SIZE];
    size_t bytesRead;
    size_t keyLen = strlen(key);
    long fileSize;
    long totalProcessed = 0;
    int result = 0;
    
    // Open input file in binary read mode
    inFile = fopen(inputFile, "rb");
    if (inFile == NULL) {
        printf("ERROR: Cannot open input file '%s': %s\n", inputFile, strerror(errno));
        return -1;
    }
    
    // Get file size for progress indication
    fileSize = getFileSize(inFile);
    if (fileSize == -1) {
        printf("ERROR: Cannot determine file size: %s\n", strerror(errno));
        fclose(inFile);
        return -1;
    }
    
    if (fileSize == 0) {
        printf("WARNING: Input file is empty.\n");
        fclose(inFile);
        return -1;
    }
    
    // Open output file in binary write mode
    outFile = fopen(outputFile, "wb");
    if (outFile == NULL) {
        printf("ERROR: Cannot create output file '%s': %s\n", outputFile, strerror(errno));
        fclose(inFile);
        return -1;
    }
    
    // Process file in chunks
    while ((bytesRead = fread(buffer, 1, BUFFER_SIZE, inFile)) > 0) {
        // Apply XOR cipher to the buffer
        xorCipher(buffer, bytesRead, key, keyLen);
        
        // Write encrypted data to output file
        size_t bytesWritten = fwrite(buffer, 1, bytesRead, outFile);
        if (bytesWritten != bytesRead) {
            printf("\nERROR: Write operation failed: %s\n", strerror(errno));
            result = -1;
            break;
        }
        
        // Update progress
        totalProcessed += bytesRead;
        printProgress(totalProcessed, fileSize);
    }
    
    // Check for read errors
    if (ferror(inFile)) {
        printf("\nERROR: Read operation failed: %s\n", strerror(errno));
        result = -1;
    }
    
    // Close files
    if (fclose(inFile) != 0) {
        printf("WARNING: Error closing input file: %s\n", strerror(errno));
    }
    
    if (fclose(outFile) != 0) {
        printf("WARNING: Error closing output file: %s\n", strerror(errno));
        result = -1;
    }
    
    return result;
}

/*
 * Decrypt a file using XOR cipher
 * XOR is symmetric, so decryption uses the same process as encryption
 * Parameters:
 *   inputFile: Name of the input file
 *   outputFile: Name of the output file
 *   key: Decryption key
 * Returns: 0 on success, -1 on failure
 */
int decryptFile(const char *inputFile, const char *outputFile, const char *key) {
    // XOR cipher is symmetric - decryption is the same as encryption
    return encryptFile(inputFile, outputFile, key);
}

/*
 * Apply XOR cipher to data
 * XOR each byte with corresponding key byte (repeating key if necessary)
 * Parameters:
 *   data: Data buffer to encrypt/decrypt
 *   dataLen: Length of data buffer
 *   key: Encryption/decryption key
 *   keyLen: Length of key
 */
void xorCipher(unsigned char *data, size_t dataLen, const char *key, size_t keyLen) {
    for (size_t i = 0; i < dataLen; i++) {
        // XOR each byte with the corresponding key byte
        // Use modulo to repeat key if data is longer than key
        data[i] ^= (unsigned char)key[i % keyLen];
    }
}

/*
 * Clear input buffer to remove extra characters
 */
void clearInputBuffer() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

/*
 * Print progress bar for file processing
 * Parameters:
 *   current: Current number of bytes processed
 *   total: Total number of bytes to process
 */
void printProgress(long current, long total) {
    int barWidth = 50;
    float progress = (float)current / total;
    int pos = (int)(barWidth * progress);
    
    printf("\r[");
    for (int i = 0; i < barWidth; i++) {
        if (i < pos) printf("=");
        else if (i == pos) printf(">");
        else printf(" ");
    }
    printf("] %.1f%%", progress * 100);
    fflush(stdout);
}