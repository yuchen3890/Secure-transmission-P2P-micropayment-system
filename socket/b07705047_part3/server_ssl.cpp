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
#include <queue>

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

using namespace std;
//cd /mnt/c/Users/user/Desktop/socket
//g++ -pthread -o server_s server_ssl.cpp

const int LEN = 1000;
const int IN_PUT = 32;
const int USER_NUM = 10;
const int CLIENT_LEN = 2;

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

void ShowCerts(SSL* ssl)
{
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Client certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}

class Client{
public:
    SSL* ssl;
    int Sockfd;
    struct sockaddr_in Info;
    bool isConnected;

    Client(){}
    Client(SSL* ssl, int clientSockfd, struct sockaddr_in clientInfo, bool isConnected): ssl(ssl), Sockfd(clientSockfd), Info(clientInfo), isConnected(isConnected){} 
};



queue<Client*> waiting;
void* handleConnection(void* C);
void afterLogin(Client* c, char* userName, char* message_List);


class User
{
public:
    bool login;
    char userName[IN_PUT] = {0};
    char userIP[LEN] = {0};
    char userPort[IN_PUT] = {0};
    int accountBalance;
    RSA* rsa;

    //constructor
    User(int login, char* userName, int d) : login(login), accountBalance(d){
        strcat(this->userName, userName);
    }
};

class UserDB
{
public:
    User **userPtr;
    int len = 0;
    // constructor
    UserDB(){
        this->userPtr = new User *[USER_NUM];
    }

    void regist(Client* c, char* receiveMessage);
    void login(Client* c, char* receiveMessage, char* userName, char* userPort);
    void List(Client* c, char* userName);
    void Exit(Client* c);
    void Pay(char* receiveMessage);
};

UserDB userDB; // initialize a pointer pointing to each user's "user"

void UserDB::regist(Client* c, char* receiveMessage){

    char message[LEN] = {0};
    char userName[IN_PUT] = {0};
    char depositAmount[IN_PUT] = {0};
    char discard[IN_PUT] = {0};
    char *pch = strtok(receiveMessage, "#"); // 第一坨是REGISTER捨棄
    strcat(discard, pch);
    pch = strtok(NULL, "#");
    // cout << pch << "\n";
    strcat(userName, pch);
    // cout << userName << "\n";
    pch = strtok(NULL, "#");
    strcat(depositAmount, pch);
    int d = atoi(depositAmount);
    // if there exists a same userName
    for(int i = 0; i < userDB.len; i++){
        if(strcmp(userDB.userPtr[i]->userName, userName) == 0){
            strcat(message, "210<space>FAIL\n");
            SSL_write(c->ssl, message, strlen(message));
            bzero(message, sizeof(message));
            return;
        }
    }
    // no repeated userName
    strcat(message, "100<space>OK\n");
    SSL_write(c->ssl, message, strlen(message));
    bzero(message, sizeof(message));

    User* u = new User(0, userName, d);
    userDB.userPtr[userDB.len] = u;
    userDB.len++;
}

void UserDB::login(Client* c, char* receiveMessage, char* userName, char* userPort){
    
    char message[LEN] = {0};
    // register or not 
    bool exist = 0;
    
    // cout << userDB.userPtr[0]->userName << " \n";
    for(int i = 0; i < userDB.len; i++)
    {
        // cout << i << userDB.userPtr[i]->userName;
        if (strcmp(userDB.userPtr[i]->userName, userName) == 0)
        {
            // cout << userName << "\n";
            exist = 1;
            userDB.userPtr[i]->login = 1;
            strcat(userDB.userPtr[i]->userPort, userPort);
            strcat(userDB.userPtr[i]->userIP, inet_ntoa(c->Info.sin_addr));
            break;
        }
    }

    if(exist == 0){
        // cout << exist << "\n";
        strcat(message, "220<space>AUTH_FAIL\n");
        SSL_write(c->ssl, message, strlen(message));
        bzero(message, sizeof(message));
        return;
    }

    userDB.List(c, userName);
    afterLogin(c, userName, message);
    return;

}

void UserDB::List(Client* c, char* userName){

    char message[LEN] = {0};
    int accountBalance = 0;
    // register or not 
    for(int i = 0; i < userDB.len; i++)
    {
        if (strcmp(userDB.userPtr[i]->userName, userName) == 0)
        {
            accountBalance = userDB.userPtr[i]->accountBalance;
            break;
        }
    }

    int online = 0;
    for(int i = 0; i < userDB.len; i++)
    {
        if(userDB.userPtr[i]->login == 1)
        {
            online++;
        }
    }
    
    string tmp1 = to_string(accountBalance);
    const char* a = tmp1.c_str();
    string tmp2 = to_string(online);
    const char* o = tmp2.c_str();

    strcat(message, a);
    strcat(message, "\n");
    strcat(message, o);
    strcat(message, "\n");
    for(int i = 0; i < userDB.len; i++)
    {
        if (userDB.userPtr[i]->login == 1)
        {
            strcat(message, userDB.userPtr[i]->userName);
            strcat(message, "#");
            strcat(message, userDB.userPtr[i]->userIP);
            strcat(message, "#");
            strcat(message, userDB.userPtr[i]->userPort);
        }
    }
    SSL_write(c->ssl, message, strlen(message));
    bzero(message, sizeof(message));
    return;
}

void UserDB::Exit(Client* c){
    char message[LEN] = {0};
    char receiveMessage[LEN] = {0};
    strcat(message, "Bye");
    SSL_write(c->ssl, message, strlen(message));
    SSL_read(c->ssl, receiveMessage, sizeof(receiveMessage));
    cout << receiveMessage << "\n";
    bzero(message, sizeof(message));
    bzero(receiveMessage, sizeof(receiveMessage));
    return;
}

void UserDB::Pay(char* receiveMessage){

    int pos = 0;
    for(int i = 0; i < strlen(receiveMessage); i++){
        if(receiveMessage[i] == '$'){
            pos = i;
            break;
        }
    }
    char rcv[LEN] = {0};
    strncat(rcv, receiveMessage, pos);
    char payerName[IN_PUT] = {0};
    char payeeName[IN_PUT] = {0};
    char payAmount[IN_PUT] = {0};
    char discard[IN_PUT] = {0};
    
    
    char* pch = strtok(rcv, "#");
    strcat(discard, pch);
    pch = strtok(NULL, "#");
    strcat(payerName, pch);
    pch = strtok(NULL, "#");
    strcat(payAmount, pch);
    pch = strtok(NULL, "\0");
    strcat(payeeName, pch);

    //no confirm format
    char compareText[LEN] = {0};
    strcat(compareText, payerName);
    strcat(compareText, "#");
    strcat(compareText, payAmount);
    strcat(compareText, "#");
    strcat(compareText, payeeName);

    RSA* payeeKey;
    RSA* payerKey;

    //先拿payee的公鑰解密
    for(int i = 0; i < userDB.len; i++){
        if(strcmp(userDB.userPtr[i]->userName, payeeName) == 0){
            payeeKey = userDB.userPtr[i]->rsa;
        }
        if(strcmp(userDB.userPtr[i]->userName, payerName) == 0){
            payerKey = userDB.userPtr[i]->rsa;
        }
    }
    //解密密文
    //切成兩段密文
    char cipher_front[256] = {0};
    char cipher_back[256] = {0};
    int CNT = pos+1;
    for(int i = 0; i < 256; i++){
        cipher_front[i] = receiveMessage[CNT];
        CNT++;
    }
    for(int i = 0; i < 256; i++){
        cipher_back[i] = receiveMessage[CNT];
        CNT++;
    }

    char cipher1[128] = {0};
    char cipher2[128] = {0};
    //用payee公鑰解密
    int res = RSA_public_decrypt(256, (unsigned char *)cipher_front, (unsigned char *)cipher1, payeeKey, RSA_PKCS1_PADDING);
    if (res == -1){
        ERR_print_errors_fp(stderr);
    }
    res = RSA_public_decrypt(256, (unsigned char *)cipher_back, (unsigned char *)cipher2, payeeKey, RSA_PKCS1_PADDING);
    if (res == -1){
        ERR_print_errors_fp(stderr);
    }
    //concate第一階段解密密文
    char cipher12[LEN];
    int count = 0;
    for(int i = 0; i < 128; i++){
        cipher12[count] = cipher1[i]; 
        count++;
    }
    for(int i = 0; i < 128; i++){
        cipher12[count] = cipher2[i]; 
        count++;
    }
    //用payer公鑰解密
    char plainText[LEN];
    res = RSA_public_decrypt(count, (unsigned char *)cipher12, (unsigned char *)plainText, payerKey, RSA_PKCS1_PADDING);
    if (res == -1){
        ERR_print_errors_fp(stderr);
    }
    cout << "\nplain text:" << plainText << "\n";
    cout << "compareText:" << compareText << "\n";
    if(strcmp(plainText, compareText) == 0){
        // 確認沒被駭客攻擊即更新
        int money = 0;
        money = atoi(payAmount);

        for(int i = 0; i < userDB.len; i++){
            if(strcmp(userDB.userPtr[i]->userName, payerName) == 0){
                if(userDB.userPtr[i]->accountBalance >= money){
                    userDB.userPtr[i]->accountBalance -= money;
                }
                else
                {
                    cout << "payer " << payerName << " remitting money to " << payeeName << " is failed.\n";
                    return;
                }
                break;
            }
            
        }
        for(int i = 0; i < userDB.len; i++){
            if(strcmp(userDB.userPtr[i]->userName, payeeName) == 0){
                userDB.userPtr[i]->accountBalance += money;
                break;
            }
        }
    }
    else{
        cout << "You are hacked! QQQQ \n";
    }
    return;
}



void* handleConnection(void* C)
{
    Client* c = (Client*) C;
    char message[LEN] = {0};
    char receiveMessage[LEN] = {0};
    strcat(message, "Connection accepted.\n");
    cout << message << "\n";
    SSL_write(c->ssl, message, strlen(message));
    bzero(message, sizeof(message));

    while (true)
    {
        SSL_read(c->ssl, receiveMessage, sizeof(receiveMessage));
        cout << "receive:\n" << receiveMessage << "\n";
        // register
        if (strstr(receiveMessage, "REGISTER") != NULL){
            userDB.regist(c, receiveMessage);
            bzero(receiveMessage, sizeof(receiveMessage));
            continue;
        }
        // cout << receiveMessage << "\n";
        // login or not
        char userName[LEN] = {0};
        char userPort[LEN] = {0};
        char rcv[LEN] = {0};
        strcat(rcv, receiveMessage);
        char *pch = strtok(rcv, "#");
        strcat(userName, pch);
        pch = strtok(NULL, "\0");
        strcat(userPort, pch);
        pch = strtok(NULL, "#"); // if there's only one "#", then pch == null
        // cout << receiveMessage << " wrong here\n";
        if (pch == NULL)
        {
            // cout << receiveMessage << "\n";
            userDB.login(c, receiveMessage, userName, userPort);
            bzero(userName, sizeof(userName));
            bzero(userPort, sizeof(userPort));
            bzero(receiveMessage, sizeof(receiveMessage));
            c->isConnected = 0;
            return NULL;
        }  
        //wrong message handling
        else{
            char message[LEN] = {0};
            strcat(message, "Wrong message, please send again.");
            SSL_write(c->ssl, message, strlen(message));
            bzero(message, sizeof(message));

        }
    }
};

void afterLogin(Client* c, char* userName, char* message_List){
    char message[LEN] = {0};
    char receiveMessage[LEN] = {0};
    
    //取得user憑證
    X509 * client_cer = SSL_get_peer_certificate(c->ssl);
    //取得user公鑰
    EVP_PKEY * client_pubKey = X509_get_pubkey(client_cer);
    //將公鑰型態轉為RSA
    RSA * rsa = EVP_PKEY_get1_RSA(client_pubKey);
    for(int i = 0; i < userDB.len; i++){
        if (strcmp(userDB.userPtr[i]->userName, userName) == 0)
        {
            userDB.userPtr[i]->rsa = rsa;
        }
    }
    
    

    
    while(true){
        SSL_read(c->ssl, receiveMessage, sizeof(receiveMessage));
        // list
        if(strcmp(receiveMessage, "List") == 0){
            userDB.List(c, userName);
            bzero(&message, sizeof(message));
            bzero(&receiveMessage, sizeof(receiveMessage));
            continue;
        }
        // exit
        if(strcmp(receiveMessage, "Exit") == 0){
            userDB.Exit(c);
            bzero(&message, sizeof(message));
            bzero(&receiveMessage, sizeof(receiveMessage));
            for(int i = 0; i < userDB.len; i++){
                if(strcmp(userDB.userPtr[i]->userName, userName) == 0){
                    userDB.userPtr[i]->login = 0;
                    bzero(userDB.userPtr[i]->userPort, sizeof(userDB.userPtr[i]->userPort));
                    bzero(userDB.userPtr[i]->userIP, sizeof(userDB.userPtr[i]->userIP));
                }
            }
            return;
        }
        if (strstr(receiveMessage, "CONFIRM") != NULL){
            userDB.Pay(receiveMessage);
            bzero(&message, sizeof(message));
            bzero(&receiveMessage, sizeof(receiveMessage));
            continue;
        }
    }
    
};

void* workpool(void* param){

    Client** client = (Client **) param;
    while(true){
        if(waiting.size() != 0){
            Client* c = waiting.front();
            for(int i = 0; i < CLIENT_LEN; i++){
                if(client[i] == nullptr){
                    waiting.pop();
                    c->isConnected = 1;
                    client[i] = c;
                    cout << "clentIP:" << inet_ntoa(client[i]->Info.sin_addr) << "; clientPort:" << ntohs(client[i]->Info.sin_port) << " connected" << "\n";
                    pthread_t pID;
                    pthread_create(&pID, NULL, &handleConnection, client[i]);
                    break;
                }
                else if(client[i]->isConnected == 0){
                    waiting.pop();
                    c->isConnected = 1;
                    client[i] = c;
                    cout << "clentIP:" << inet_ntoa(client[i]->Info.sin_addr) << "; clientPort:" << ntohs(client[i]->Info.sin_port) << " connected" << "\n";
                    pthread_t pID;
                    pthread_create(&pID, NULL, &handleConnection, client[i]);
                    break;
                }
            }
        }
    }
};

int main(int argc, char *argv[])
{
    SSL_CTX *ctx;
    ctx = InitServerCTX();        /* initialize SSL */
    LoadCertificates(ctx, "server.crt", "server.key"); /* load certs */
    char receiveMessage[LEN] = {0};
    int serverSockfd = 0, clientSockfd = 0;
    serverSockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (serverSockfd == -1)
    {
        printf("Fail to create a socket.");
        return 0;
    }

    //socket connection
    struct sockaddr_in serverInfo, clientInfo;
    socklen_t addrlen = sizeof(clientInfo);
    bzero(&serverInfo, sizeof(serverInfo));

    serverInfo.sin_family = AF_INET;
    serverInfo.sin_addr.s_addr = INADDR_ANY;

    int portNum = 0;
    cout << "Please enter a port number to listen to:";
    cin >> portNum;

    serverInfo.sin_port = htons(portNum);

    
    int b = 0;
    b = bind(serverSockfd, (struct sockaddr *)&serverInfo, sizeof(serverInfo));
    if (b == -1)
    {
        cout << "Fail to bind. \n";
        return 0;
    }
    int l = 0;
    l = listen(serverSockfd, SOMAXCONN); //SOMAXCONN: listening without any limit
    if (l == -1)
    {
        cout << "Fail to listen. \n";
        return 0;
    }
    cout << "Waiting for connection... \n";
    
    Client** client = new Client* [CLIENT_LEN];

    pthread_t pID;
    pthread_create(&pID, NULL, &workpool, client);

    // Initialize the SSL library
    SSL_library_init();
    //load client 憑證
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_load_verify_locations(ctx, "clients.crt", NULL);
    
    while(true){
        clientSockfd = accept(serverSockfd, (struct sockaddr *)&clientInfo, &addrlen);
        if (clientSockfd < 0){
        cout << "Failed to accept.\n";
        }
        SSL *ssl;
        ssl = SSL_new(ctx);              /* get new SSL state with context */
        SSL_set_fd(ssl, clientSockfd);      /* set connection socket to SSL state */
        if ( SSL_accept(ssl) == -1 )     /* do SSL-protocol accept */
        {
            ERR_print_errors_fp(stderr);
            close(clientSockfd);
            continue;
        }
        ShowCerts(ssl);        /* get any certificates */ 

        Client* c = new Client(ssl, clientSockfd, clientInfo, 0);
        waiting.push(c);
        char message[LEN] = {0};
        strcat(message, "Waiting in the queue...\n");
        SSL_write(c->ssl, message, strlen(message));
        bzero(&message, sizeof(message));
    }
    close(serverSockfd);          /* close server socket */
    SSL_CTX_free(ctx);         /* release context */

    return 0;
}





