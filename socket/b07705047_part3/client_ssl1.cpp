#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <string>
#include <cstring>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fstream>
using namespace std;
//cd /mnt/c/Users/user/Desktop/socket
//g++ -pthread -o client_s client_ssl.cpp -lcrypto -lssl

const int LEN = 10000;
const int IN_PUT = 32;
void login(SSL* ssl, char* portNum);
void* sendsocket(void* parm);
SSL* ssl; // global ssl
int serverSockfd = 0; // global serverSockfd

RSA *PEM_read_RSAPrivateKey(FILE *fp, RSA **x, pem_password_cb *cb, void *u);

SSL_CTX* InitServerCTX(void)
{
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    ctx = SSL_CTX_new(SSLv23_server_method());   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

SSL_CTX* InitCTX(void)
{
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    ctx = SSL_CTX_new(SSLv23_client_method());   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
void ShowCerts(SSL* ssl)
{
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("Info: No client certificates configured.\n");
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}


void* sendsocket(void* parm){
    //initialize a socket
    char cipher[LEN];
    int sockfd = 0, forClientSockfd = 0;
    sockfd = socket(AF_INET , SOCK_STREAM , 0);

    if (sockfd == -1){
        printf("Fail to create a socket.");
    }

    //socket connection
    struct sockaddr_in serverInfo,clientInfo;
    socklen_t addrlen = sizeof(clientInfo);
    bzero(&serverInfo,sizeof(serverInfo));

    serverInfo.sin_family = AF_INET;
    serverInfo.sin_addr.s_addr = INADDR_ANY;

    char* portNum = (char *)parm; // socket default accepts parameter with type (void*)
    serverInfo.sin_port = htons(atoi(portNum));
    int b = 0;
    b = bind(sockfd, (struct sockaddr *)&serverInfo, sizeof(serverInfo));
    if (b == -1)
    {
        cout << "Fail to bind. \n";
        return 0;
    }
    int l = 0;
    l = listen(sockfd, SOMAXCONN); //SOMAXCONN: listening without any limit
    if (l == -1)
    {
        cout << "Fail to listen. \n";
        return 0;
    }

    SSL_CTX *ctx;
    ctx = InitServerCTX();        /* initialize SSL */
    LoadCertificates(ctx, "client1.crt", "client1.key"); /* load certs */
    SSL_library_init();
    //load client ??????
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_load_verify_locations(ctx, "clients.crt", NULL);
    cout << "listen on " << portNum << "\n";

    while(true){
        forClientSockfd = accept(sockfd,(struct sockaddr*) &clientInfo, &addrlen);
        SSL *ssl2;
        ssl2 = SSL_new(ctx);              /* get new SSL state with context */
        SSL_set_fd(ssl2, forClientSockfd);      /* set connection socket to SSL state */
        if (SSL_accept(ssl2) == -1)     /* do SSL-protocol accept */
        {
            ERR_print_errors_fp(stderr);
            close(forClientSockfd);
            continue;
        }
        ShowCerts(ssl2);        /* get any certificates */  
        char message[LEN] = {0};
        strcat(message, "Connection accepted.");
        SSL_write(ssl2,message,sizeof(message));

        SSL_read(ssl2,cipher,sizeof(cipher));
        cout << cipher << "\n";
        //??????A??????
        X509 * client_cer = SSL_get_peer_certificate(ssl2);
        //??????A??????
        EVP_PKEY * client_pubKey = X509_get_pubkey(client_cer);
        //?????????????????????RSA
        RSA * rsa = EVP_PKEY_get1_RSA(client_pubKey);
        char plainText[1000] = {0};
        int res = RSA_public_decrypt(256, (unsigned char *)cipher, (unsigned char *)plainText, rsa, RSA_PKCS1_PADDING);
        if (res == -1){
            ERR_print_errors_fp(stderr);
        }
        //???cipher????????????(?????????rsa-2048???????????????256-11??????????????????????????????????????????????????????)
        char cipher1[128] = {0};
        char cipher2[128] = {0};
        int CNT1 = 0;
        int CNT2 = 0;
        for(int i = 0; i < 256; i++){
            if(i < 128){
                cipher1[CNT1] = cipher[i];
                CNT1 ++;
            }
            else{
                cipher2[CNT2] = cipher[i];
                CNT2++;
            }
        }
        //????????????cipher1, cipher2
        FILE* fp;
        fp = fopen("client1.key", "r");
        //????????????
        rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
        //????????????cipher1, cipher2
        char secret1[LEN] = {0};
        char secret2[LEN] = {0};
        res = RSA_private_encrypt(128*sizeof(char), (unsigned char*)cipher1, (unsigned char*)secret1, rsa, RSA_PKCS1_PADDING);
        if (res == -1){
            ERR_print_errors_fp(stderr);
        }
        res = RSA_private_encrypt(128*sizeof(char), (unsigned char*)cipher2, (unsigned char*)secret2, rsa, RSA_PKCS1_PADDING);
        if (res == -1){
            ERR_print_errors_fp(stderr);
        }
        // concate plainText, secret1, secret2
        char concateMessage[LEN] = {0};
        strcat(concateMessage, "CONFIRM#");
        strcat(concateMessage, plainText);
        strcat(concateMessage, "$");
        int CNT3 = strlen(concateMessage);
        for(int j = 0; j < 256; j++){
            concateMessage[CNT3] = secret1[j];
            CNT3++;
        }
        for(int j = 0; j < 256; j++){
            concateMessage[CNT3] = secret2[j];
            CNT3++;
        }
        
        bzero(message,sizeof(message));
        int a = 0;
        a = SSL_write(ssl,concateMessage,CNT3); // ??????server
        if(a <0){
            cout <<"Fail to send message to server.\n";
        }
        strcat(message, "Payee receive message successfully.\n");
        SSL_write(ssl2,message,sizeof(message));
        bzero(message,sizeof(message));
    }
    return NULL;
}

int main(int argc , char *argv[])
{
    
	//initialize a socket
    serverSockfd = socket(AF_INET , SOCK_STREAM , 0); // domain: AF_INET????????????IPv4??????; type: SOCK_STREAM -> protocol???TCP; protocol: default 0

    if (serverSockfd == -1){
        cout << "Fail to create a socket.";
    }

    //socket connection
    struct sockaddr_in info;
    bzero(&info,sizeof(info));
    info.sin_family = AF_INET;

    // local host test, IP = 0.0.0.0 or 127.0.0.1
    char server_IP[LEN];
    int server_port = 0;
    cout << "Please enter server's IP:";
    cin >> server_IP;
    info.sin_addr.s_addr = inet_addr(server_IP); // inet_addr()????????????????????????IP????????????????????????IP???
    cout << "Please enter server's port number:";
    cin >> server_port;
    info.sin_port = htons(server_port);

    //Send a message to server
    char receiveMessage[LEN]; // buffer size
    SSL_CTX *ctx = InitCTX();
    SSL_library_init();
    LoadCertificates(ctx, "client1.crt", "client1.key"); /* load certs */
    // connect: get data from others
    int err = connect(serverSockfd, (struct sockaddr *)&info, sizeof(info));
    if(err == -1){
        cout << "Connection error. \n";
        return 0;
    }
    ssl = SSL_new(ctx);      /* create new SSL connection state */
    SSL_set_fd(ssl, serverSockfd);    /* attach the socket descriptor */
    if (SSL_connect(ssl) == -1)   /* perform the connection */
        ERR_print_errors_fp(stderr);
    ShowCerts(ssl);
    //waiting int the queue message
    SSL_read(ssl,receiveMessage,sizeof(receiveMessage));
    cout << receiveMessage << "\n";
    bzero(receiveMessage,sizeof(receiveMessage));
    //connect accepted message
    SSL_read(ssl,receiveMessage,sizeof(receiveMessage));
    cout << receiveMessage << "\n";
    bzero(receiveMessage,sizeof(receiveMessage));


    char message[LEN]; // message send to server
    while(true){
        string q;
        cout << "If you want to shut down, please type \"s\" of \"S\" \n";
        cout << "If you want to register, please type \"r\" of \"R\" \n";
        cout << "If you want to login, please type \"l\" or \"L\" \n";
        cin >> q;

        if(q == "s" || q == "S"){
            return 0;
        }
        //register
        else if(q == "r" || q == "R"){
            char userName[IN_PUT];
            char depositAmount[IN_PUT];
            cout << "Please enter your username:";
            cin >> userName;
            cout << "Please enter the amount to deposit:";
            cin >> depositAmount;

            strcat(message, "REGISTER#");
            strcat(message, userName);
            strcat(message, "#");
            strcat(message, depositAmount);
            strcat(message, "\n");

            SSL_write(ssl,message,strlen(message));
            SSL_read(ssl,receiveMessage,sizeof(receiveMessage));
            cout << receiveMessage;
            if(receiveMessage == "210 FAIL"){
                cout << "The username has been used!";
            }
            bzero(receiveMessage,sizeof(receiveMessage));
            bzero(message,sizeof(message));
            continue;
        }
        //login
        else if(q == "l" || q == "L"){
            char userName[IN_PUT];
            cout << "Please enter your username:";
            cin >> userName;
            char portNum[IN_PUT];
            cout << "Please enter a port number:";
            cin >> portNum;
            strcat(message, userName);
            strcat(message, "#");
            strcat(message, portNum);
            strcat(message, "\n");
            SSL_write(ssl,message,strlen(message));
            SSL_read(ssl,receiveMessage,sizeof(receiveMessage));
            bzero(message,sizeof(message));
            cout << receiveMessage;
            if(receiveMessage != "220<space>AUTH_FAIL"){
                login(ssl, portNum);
                SSL_free(ssl);        /* release connection state */
                close(serverSockfd);         /* close socket */
                SSL_CTX_free(ctx);        /* release context */
                return 0;
            }
            bzero(receiveMessage,sizeof(receiveMessage));
            bzero(message,sizeof(message));
        }
        else{
            cout << "Wrong query, please type again: \n";
        }
    }
    
    return 0;
}

void login(SSL* ssl, char* portNum){
    // message sending between client 
    pthread_t pID;
	pthread_create(&pID, NULL, &sendsocket, portNum); 
	// pthread_join(pID, NULL); // ????????????main thread ??? pthread ????????????????????????????????????output????????????

    char receiveMessage[LEN];
    char message[IN_PUT]; // message send to server 
    while(true){
        string q; // query     
        cout << "If you want to check your account balance and online list, please type \"a\" or \"A\" \n";
        cout << "If you want to exit, please type \"e\" or \"E\" \n";
        cout << "If you want to remit money to another client, please type \"p\" or \"P\" \n";
        cin >> q;

        // account balance and online list
        if(q == "a" || q == "A"){
            strcat(message, "List");
            SSL_write(ssl,message,strlen(message));
            SSL_read(ssl,receiveMessage,sizeof(receiveMessage));
            cout << receiveMessage;
            bzero(receiveMessage,sizeof(receiveMessage));
            bzero(message,sizeof(message));
        }
        
        //Exit
        else if(q == "e" || q == "E"){
            strcat(message, "Exit");
            SSL_write(ssl,message,strlen(message));
            SSL_read(ssl,receiveMessage,sizeof(receiveMessage));
            cout << receiveMessage << "\n";
            bzero(receiveMessage,sizeof(receiveMessage));
            bzero(message,sizeof(message));
            strcat(message, "Listening port number = ");
            strcat(message, portNum);
            strcat(message, " user exit");
            SSL_write(ssl,message,strlen(message));
            bzero(message,sizeof(message));
            close(serverSockfd);
            break;
        }

        // between client
        else if(q == "p" || q == "P"){  

            cout << "This is a list of your account balance, number of users online and their information: \n";
            strcat(message, "List");
            SSL_write(ssl,message,strlen(message));
            SSL_read(ssl,receiveMessage,sizeof(receiveMessage));
            cout << receiveMessage;
            
            char payee_IP[LEN];
            int payee_port = 0;
            char payee_name[IN_PUT];
            cout << "Please enter the payee's username: ";
            cin >> payee_name;
            
            char* pch = strstr(receiveMessage, payee_name);
            if(pch == nullptr){
                cout << "Wrong payeename.\n";
                bzero(receiveMessage,sizeof(receiveMessage));
                bzero(message,sizeof(message));
                continue;
            }
            pch = strtok(pch, "#");
            pch = strtok(NULL, "#");
            strcat(payee_IP, pch);
            pch = strtok(NULL, "#");
            payee_port = atoi(pch);

            bzero(receiveMessage,sizeof(receiveMessage));
            bzero(message,sizeof(message));

            // initialize a socket
            int sockfd = 0;
            sockfd = socket(AF_INET , SOCK_STREAM , 0); // domain: AF_INET????????????IPv4??????; type: SOCK_STREAM -> protocol???TCP; protocol: default 0

            if (sockfd == -1){
                cout << "Fail to create a socket.";
            }

            //connection
            struct sockaddr_in sock_toClient;
            bzero(&sock_toClient,sizeof(sock_toClient));
            sock_toClient.sin_family = AF_INET;

            sock_toClient.sin_addr.s_addr = inet_addr(payee_IP); 
            sock_toClient.sin_port = htons(payee_port);

            // Send a message to another client
            char receiveMessage[LEN]; 
            
            int err = connect(sockfd, (struct sockaddr *)&sock_toClient, sizeof(sock_toClient));
            if(err == -1){
                cout << "Connection error";
            }

            SSL_CTX *ctx;
            ctx = InitCTX();        /* initialize SSL */
            LoadCertificates(ctx, "client1.crt", "client1.key"); /* load certs */
            SSL_library_init();
            SSL *ssl2;
            
            ssl2 = SSL_new(ctx);              /* get new SSL state with context */
            SSL_set_fd(ssl2, sockfd);      /* set connection socket to SSL state */
            if (SSL_connect(ssl2) == -1)     /* do SSL-protocol accept */
            {
                ERR_print_errors_fp(stderr);
                close(sockfd);
                continue;
            }
            ShowCerts(ssl2);        /* get any certificates */  

            SSL_read(ssl2,receiveMessage,sizeof(receiveMessage));
            cout << receiveMessage << "\n";
            bzero(receiveMessage,sizeof(receiveMessage));

            char userName[IN_PUT] = {0};
            char payAmount[IN_PUT] = {0};
            cout << "Please enter your user name:";
            cin >> userName;

            if(strcmp(payee_name, userName) == 0){
                cout << "You cannot remit money to yourself.\n";
                bzero(receiveMessage,sizeof(receiveMessage));
                bzero(message,sizeof(message));
                continue;
            }

            cout << "Please enter the amount:";
            cin >> payAmount;
            strcat(message, userName);
            strcat(message, "#");
            strcat(message, payAmount);
            strcat(message, "#");
            strcat(message, payee_name);
            cout << message << "\n";

            //??????
            FILE* fp;
            fp = fopen("client1.key", "r");
            //????????????
            RSA* rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
            //????????????
            unsigned char* m;
            m = (unsigned char*)message;  
            char secret[1000] = {0};
            int res = RSA_private_encrypt((strlen(message)+1)*sizeof(char), m, (unsigned char*)secret, rsa, RSA_PKCS1_PADDING);
            if (res == -1){
                ERR_print_errors_fp(stderr);
            }

            SSL_write(ssl2, secret, 256);
            SSL_read(ssl2,receiveMessage,sizeof(receiveMessage));
            cout << receiveMessage << "\n";
            bzero(receiveMessage,sizeof(receiveMessage));
            bzero(message,sizeof(message));
        }
        else{
            cout << "Wrong query, please type again: \n";
        }    
    }
    return;
} 





