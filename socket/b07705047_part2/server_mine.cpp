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
using namespace std;
//cd /mnt/c/Users/user/Desktop/
//g++ -pthread -o server_n server_new.cpp

const int LEN = 1000;
const int IN_PUT = 32;
const int USER_NUM = 10;
const int CLIENT_LEN = 2;



class Client{
public:
    int Sockfd;
    struct sockaddr_in Info;
    bool isConnected;

    Client(){}
    Client(int clientSockfd, struct sockaddr_in clientInfo, bool isConnected): Sockfd(clientSockfd), Info(clientInfo), isConnected(isConnected){} 
};



queue<Client*> waiting;
void* handleConnection(void* C);
void afterLogin(Client* c, char* userName, char* message_List);


class User
{
public:
    bool login;
    char userName[IN_PUT];
    char userIP[LEN];
    char userPort[IN_PUT];
    int accountBalance;

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

    char message[LEN];
    char userName[IN_PUT];
    char depositAmount[IN_PUT];
    char discard[IN_PUT];
    char *pch = strtok(receiveMessage, "#"); // 第一坨是REGISTER捨棄
    strcat(discard, pch);
    pch = strtok(NULL, "#");
    strcat(userName, pch);
    pch = strtok(NULL, "#");
    strcat(depositAmount, pch);
    int d = atoi(depositAmount);
    // if there exists a same userName
    for(int i = 0; i < userDB.len; i++){
        if(strcmp(userDB.userPtr[i]->userName, userName) == 0){
            strcat(message, "210<space>FAIL\n");
            send(c->Sockfd, message, strlen(message), 0);
            bzero(message, sizeof(message));
            return;
        }
    }
    // no repeated userName
    strcat(message, "100<space>OK\n");
    send(c->Sockfd, message, strlen(message), 0);
    bzero(message, sizeof(message));
    User* u = new User(0, userName, d);
    userDB.userPtr[userDB.len] = u;
    userDB.len++;
}

void UserDB::login(Client* c, char* receiveMessage, char* userName, char* userPort){

    char message[LEN];
    // register or not 
    bool exist = 0;
    
    for(int i = 0; i < userDB.len; i++)
    {
        if (strcmp(userDB.userPtr[i]->userName, userName) == 0)
        {
            exist = 1;
            userDB.userPtr[i]->login = 1;
            strcat(userDB.userPtr[i]->userPort, userPort);
            strcat(userDB.userPtr[i]->userIP, inet_ntoa(c->Info.sin_addr));
            break;
        }
    }

    if(exist == 0){
        strcat(message, "220<space>AUTH_FAIL\n");
        send(c->Sockfd, message, strlen(message), 0);
        bzero(message, sizeof(message));
        return;
    }

    userDB.List(c, userName);
    afterLogin(c, userName, message);
    return;

}

void UserDB::List(Client* c, char* userName){

    char message[LEN];
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
    send(c->Sockfd, message, strlen(message), 0);
    bzero(message, sizeof(message));
    return;
}

void UserDB::Exit(Client* c){
    char message[LEN];
    char receiveMessage[LEN];
    strcat(message, "Bye");
    send(c->Sockfd, message, strlen(message), 0);
    recv(c->Sockfd,receiveMessage,sizeof(receiveMessage),0);
    cout << receiveMessage << "\n";
    bzero(message, sizeof(message));
    bzero(receiveMessage, sizeof(receiveMessage));
    return;
}

void UserDB::Pay(char* receiveMessage){
    char payerName[IN_PUT];
    char payeeName[IN_PUT];
    char payAmount[IN_PUT];
    char discard[IN_PUT];
    char* pch = strtok(receiveMessage, "#");
    strcat(discard, pch);
    pch = strtok(NULL, "#");
    strcat(payerName, pch);
    pch = strtok(NULL, "#");
    strcat(payAmount, pch);
    pch = strtok(NULL, "\0");
    strcat(payeeName, pch);
    int money = 0;
    money = atoi(payAmount);

    for(int i = 0; i < userDB.len; i++){
        if(strcmp(userDB.userPtr[i]->userName, payerName) == 0){
            userDB.userPtr[i]->accountBalance -= money;
        }
        if(strcmp(userDB.userPtr[i]->userName, payeeName) == 0){
            userDB.userPtr[i]->accountBalance += money;
        }
    }
    return;
}



void* handleConnection(void* C)
{
    Client* c = (Client*) C;
    char message[LEN];
    char receiveMessage[LEN];
    strcat(message, "Connection accepted.\n");
    send(c->Sockfd, message, strlen(message), 0);
    bzero(message, sizeof(message));

    while (true)
    {
        recv(c->Sockfd, receiveMessage, sizeof(receiveMessage), 0);
        // register
        if (strstr(receiveMessage, "REGISTER") != NULL){
            userDB.regist(c, receiveMessage);
            bzero(receiveMessage, sizeof(receiveMessage));
            continue;
        }

        // login or not
        char userName[LEN];
        char userPort[LEN];
        char *pch = strtok(receiveMessage, "#");
        strcat(userName, pch);
        pch = strtok(NULL, "\0");
        strcat(userPort, pch);
        pch = strtok(NULL, "#"); // if there's only one "#", then pch == null
        if (pch == NULL)
        {
            userDB.login(c, receiveMessage, userName, userPort);
            bzero(userName, sizeof(userName));
            bzero(userPort, sizeof(userPort));
            bzero(receiveMessage, sizeof(receiveMessage));
            c->isConnected = 0;
            return NULL;
        }  
        //wrong message handling
        else{
            char message[LEN];
            strcat(message, "Wrong message, please send again.");
            send(c->Sockfd, message, strlen(message), 0);
            bzero(message, sizeof(message));

        }
    }
};

void afterLogin(Client* c, char* userName, char* message_List){
    char message[LEN];
    char receiveMessage[LEN];
    
    while(true){
        recv(c->Sockfd, receiveMessage, sizeof(receiveMessage), 0);
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
    char receiveMessage[LEN];
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

    while(true){
        clientSockfd = accept(serverSockfd, (struct sockaddr *)&clientInfo, &addrlen);
        if (clientSockfd < 0){
        cout << "Failed to accept. \n";
        }
        Client* c = new Client(clientSockfd, clientInfo, 0);
        waiting.push(c);
        char message[LEN];
        strcat(message, "Waiting in the queue...\n");
        send(c->Sockfd, message, strlen(message), 0);
        bzero(&message, sizeof(message));
    }

    return 0;
}





