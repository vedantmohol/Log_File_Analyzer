%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "log_analyzer.tab.h"

typedef struct {
    char token_type[50];  
    char value[100];      
} Symbol;

Symbol symbol_table[100];  
int symbol_count = 0;      

FILE *output_file;  
int validate_ip(const char *ip);
int validate_timestamp(const char *timestamp);
int validate_status(const char *status);

void add_to_symbol_table(const char *type, const char *value) {
    strcpy(symbol_table[symbol_count].token_type, type);
    strcpy(symbol_table[symbol_count].value, value);
    symbol_count++;
}
%}

%option noyywrap

%%

[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ { 
    if (validate_ip(yytext)) {
        fprintf(output_file, "Valid IP: %s\n", yytext);
        add_to_symbol_table("IP_ADDRESS", yytext);
        return IP_ADDRESS;
    } else {
        fprintf(output_file, "Invalid IP: %s\n", yytext);
    }
}

[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}-[0-9]{2}-[0-9]{2} { 
    if (validate_timestamp(yytext)) {
        fprintf(output_file, "Valid Timestamp: %s\n", yytext);
        add_to_symbol_table("TIMESTAMP", yytext);
        return TIMESTAMP;
    } else {
        fprintf(output_file, "Invalid Timestamp: %s\n", yytext);
    }
}

[0-9]{3} { 
    if (validate_status(yytext)) {
        fprintf(output_file, "Valid status code: %s\n", yytext);
        add_to_symbol_table("STATUS_CODE", yytext);
        return STATUS_CODE;
    } else {
        fprintf(output_file, "Invalid status code: %s\n", yytext);
    }
}

[0-9]+ms { 
    fprintf(output_file, "Response Time: %s\n", yytext); 
    add_to_symbol_table("RESPONSE_TIME", yytext);
    return RESPONSE_TIME; 
}

(GET|POST|PUT|DELETE) { 
    fprintf(output_file, "HTTP Method: %s\n", yytext); 
    add_to_symbol_table("HTTP_METHOD", yytext);
    return HTTP_METHOD; 
}

\/[a-zA-Z0-9_\.\-\/]+ { 
    fprintf(output_file, "URL: %s\n", yytext); 
    add_to_symbol_table("URL", yytext);
    return URL; 
}

https?:\/\/[a-zA-Z0-9\.\-\/]+ { 
    fprintf(output_file, "Referrer: %s\n", yytext); 
    add_to_symbol_table("REFERRER", yytext);
    return REFERRER; 
}

session[0-9]+ { 
    fprintf(output_file, "Session ID: %s\n", yytext); 
    add_to_symbol_table("SESSION_ID", yytext);
    return SESSION_ID; 
}

req-[0-9]+ { 
    fprintf(output_file, "Request Code: %s\n", yytext); 
    add_to_symbol_table("REQUEST_CODE", yytext);
    return REQUEST_CODE; 
}

[ \t]+ { /* Ignore whitespace */ }

\n { 
    fprintf(output_file, "Done with the log\n\n\n");
    return '\n';  
}

. { 
    fprintf(output_file, "Unknown character: %s\n", yytext); 
}

%%

int validate_ip(const char *ip) {
    int octets[4];
    if (sscanf(ip, "%d.%d.%d.%d", &octets[0], &octets[1], &octets[2], &octets[3]) == 4) {
        for (int i = 0; i < 4; i++) {
            if (octets[i] < 0 || octets[i] > 255) {
                return 0; 
            }
        }
        return 1; 
    }
    return 0; 
}

int validate_timestamp(const char *timestamp) {
    int year, month, day, hour, minute, second;
    if (sscanf(timestamp, "%2d-%2d-%2dT%2d-%2d-%2d", &year, &month, &day, &hour, &minute, &second) == 6) {
        if (hour >= 0 && hour <= 23 && minute >= 0 && minute <= 59 &&
            second >= 0 && second <= 59 && month >= 1 && month <= 12 &&
            day >= 1 && day <= 31) {
            return 1; 
        }
    }
    return 0; 
}

int validate_status(const char *status) {
    int code;
    if (sscanf(status, "%3d", &code) == 1 && code >= 100 && code <= 599) {
        return 1; 
    }
    return 0;
}
