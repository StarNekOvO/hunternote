/*
 * CTF Challenge: ret2win
 * Compile: gcc -DKEY='"YOUR_KEY_HERE"' -fno-stack-protector -no-pie -o re_checkin re_checkin.c
 * 
 * Vulnerability: Buffer overflow via gets()
 * Solution: Overflow buffer (32 bytes) + saved rbp (8 bytes) + overwrite return address with win()
 */

#include <stdio.h>
#include <stdlib.h>

#ifndef KEY
#define KEY "DEFAULT_KEY_CHANGE_ME"
#endif

// Hidden function - user needs to find and call this
void win() {
    printf("\n[+] Key: %s\n\n", KEY);
    exit(0);
}

void vulnerable() {
    char buf[32];
    
    printf("=================================\n");
    printf("       Check-in Challenge\n");
    printf("    Find the key to proceed.\n");
    printf("=================================\n\n");
    printf("Input: ");
    fflush(stdout);
    
    gets(buf);  // Vulnerable!
    
    printf("\nNice try, but that's not enough.\n");
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    
    vulnerable();
    
    return 0;
}
