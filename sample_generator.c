#include <stdio.h>
#include <string.h>
#include <sqlite3.h>

static int callback(void* data, int argc, char** argv, char** azColName) 
{ 
    int i; 
    fprintf(stderr, "%s: ", (const char*)data); 
  
    for (i = 0; i < argc; i++) { 
        printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL"); 
    } 
  
    printf("\n"); 
    return 0; 
} 
  
int main(int argc, char** argv) 
{ 
    sqlite3* DB; 
    char* messaggeError; 
    sqlite3_open("scdp_peers.db", &DB);
    int exit = sqlite3_exec(DB, "CREATE TABLE PEER(ID INT PRIMARY KEY NOT NULL, NAME TEXT NOT NULL, PROTOCOL INT NOT NULL, IP TEXT NOT NULL, PREFIX INT );", NULL, 0, &messaggeError);
    if (exit != SQLITE_OK) {
        printf("Table creation error: %s", messaggeError);
        sqlite3_free(messaggeError);
    }
    char querymsg[2000];
    sqlite3_stmt *statement = NULL;
    int count; 

    printf("STATE OF TABLE BEFORE INSERT\n");
  
    sqlite3_exec(DB, "SELET * FROM PEER;", callback, NULL, NULL); 

    strcpy(querymsg, "INSERT INTO PEER VALUES(1, 'hat', 1, '192.168.4.213', 221);"
               "INSERT INTO PEER VALUES(2, 'bowl', 1, '192.168.3.215', 222);"
               "INSERT INTO PEER VALUES(3, 'hatbowl', 1, '192.168.2.41', 223);"
               "INSERT INTO PEER VALUES(4, 'bowlerhat', 1, '192.168.5.100', 224);"
               "INSERT INTO PEER VALUES(5, 'bowl of hats', 1, '192.168.6.10', 225);"
               "INSERT INTO PEER VALUES(6, 'hat witch', 1, '192.168.7.213', 226);"
               "INSERT INTO PEER VALUES(7, 'hat warlock', 1, '192.168.8.104', 227);"
               "INSERT INTO PEER VALUES(8, 'true hat', 1, '192.168.9.16', 228);"
               "INSERT INTO PEER VALUES(9, 'impostor hat', 1, '192.168.10.161', 229);"
               "INSERT INTO PEER VALUES(10, 'fake hat', 1, '192.168.11.72', 230);"
               "INSERT INTO PEER VALUES(11, 'illegitimate hat', 1, '192.168.12.82', 231);"
               "INSERT INTO PEER VALUES(12, 'comatose hat', 1, '192.168.13.18', 232);"
               "INSERT INTO PEER VALUES(13, 'unmoving hat', 1, '192.168.14.51', 233);"
               "INSERT INTO PEER VALUES(14, 'dead hat', 1, '192.168.15.156', 234);"
               "INSERT INTO PEER VALUES(15, 'dad hat', 0, '192.168.16.7', 235);" // A couple thousand blocks; not whole NXX
               "INSERT INTO PEER VALUES(16, 'fog hat', 1, '192.168.17.41', 236);" // 2000 block
               "INSERT INTO PEER VALUES(17, 'truer hat', 1, '192.168.18.61', 237);");


    exit = sqlite3_exec(DB, querymsg, NULL, 0, &messaggeError); 
    if (exit != SQLITE_OK) { 
        fprintf(stderr, "Error Insert %s\n",messaggeError);
        sqlite3_free(messaggeError); 
    } 
    else
        printf("Records created Successfully!\n");
  
    printf("STATE OF TABLE AFTER INSERT\n");
  
    sqlite3_exec(DB, "SELECT * FROM PEER;", callback, NULL, NULL); 
    sqlite3_prepare_v2(DB, "SELECT COUNT(*) FROM PEER;", -1, &statement, 0);
    
    int result = sqlite3_step(statement);
    
    if (result == SQLITE_ROW) {
        count = sqlite3_column_int(statement, 0);
        printf("DEBUG: count is %d\n", count);
    }
    else {
        printf("ERROR: Result code was %d\n", result);
    }
    sqlite3_prepare_v2(DB, "SELECT * FROM PEER;", -1, &statement, 0);
    for (int counter = 0; counter < count; counter++) {
        result = sqlite3_step(statement);
        if (result == SQLITE_ROW) {
            printf("DEBUG: ID is %d, "\
                   "Name is %s, "\
                   "Protocol is %d, "\
                   "IP is %s, "\
                   "NXX is %d\n", 
                   sqlite3_column_int(statement, 0), 
                   sqlite3_column_text(statement, 1), 
                   sqlite3_column_int(statement, 2),
                   sqlite3_column_text(statement, 3),
                   sqlite3_column_int(statement, 4));
        }
    
        else {
            printf("ERROR Result code was %d\n", result);
        }

    }
    
    /*
    strcpy(querymsg, "SELECT COUNT(*) FROM PEER;");
    exit = sqlite3_exec(DB, querymsg, callback, NULL, &messaggeError); 
    if (exit != SQLITE_OK) { 
        fprintf(stderr, "Error SELECT COUNT(ID)\n");
        sqlite3_free(messaggeError); 
    } 
    else
        printf("Count printed!\n");
    */
  
    sqlite3_close(DB); 
    return (0); 
} 

