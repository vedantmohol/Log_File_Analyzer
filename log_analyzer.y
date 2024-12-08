%{
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    char token_type[50];
    char value[100];
} Symbol;

extern Symbol symbol_table[100];
extern int symbol_count;
extern FILE *output_file;
extern FILE *yyin;

void print_symbol_table();
void yyerror(const char *s);
int yylex();
%}

%token IP_ADDRESS TIMESTAMP STATUS_CODE RESPONSE_TIME HTTP_METHOD URL REFERRER SESSION_ID REQUEST_CODE

%%
input:
    log_entries
    ;

log_entries:
    log_entry '\n' log_entries   
    | log_entry                   
    | '\n' log_entries            
    | /* empty */                 
    ;

log_entry:
    IP_ADDRESS TIMESTAMP STATUS_CODE HTTP_METHOD URL RESPONSE_TIME REFERRER SESSION_ID REQUEST_CODE
    {
        fprintf(output_file, "Log Entry Parsed Successfully.\n");
    }
    ;

%%

void print_symbol_table() {
    fprintf(output_file, "\nSymbol Table:\n");
    for (int i = 0; i < symbol_count; i++) {
        fprintf(output_file, "%s: %s\n", symbol_table[i].token_type, symbol_table[i].value);
    }
}

void yyerror(const char *s) {
    fprintf(stderr, "Error: %s\n", s);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    yyin = fopen(argv[1], "r");
    if (!yyin) {
        fprintf(stderr, "Error opening input file: %s\n", argv[1]);
        return 1;
    }

    output_file = fopen("output.txt", "w");
    if (!output_file) {
        fprintf(stderr, "Error opening output file!\n");
        fclose(yyin);
        return 1;
    }

    printf("Starting log analysis...\n");
    yyparse();  

    print_symbol_table();  

    fclose(yyin); 
    fclose(output_file);  

    printf("Log analysis completed.\n");
    return 0;
}
