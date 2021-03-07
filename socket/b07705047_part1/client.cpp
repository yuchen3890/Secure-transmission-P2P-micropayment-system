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
using namespace std;
//cd /mnt/c/Users/user/Desktop/
//g++ -pthread -o client_m client_modified.cpp

const int LEN = 10000;
const int IN_PUT = 32;
void login(int sockfd, char* portNum);
void* sendsocket(void* parm);

void* sendsocket(void* parm){
    //initialize a socket
    char receiveMessage[LEN];
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
    bind(sockfd,(struct sockaddr *)&serverInfo,sizeof(serverInfo));
    listen(sockfd,5);

    while(true){
        forClientSockfd = accept(sockfd,(struct sockaddr*) &clientInfo, &addrlen);
        char message[LEN];
        strcat(message, "Connection accepted.");
        send(forClientSockfd,message,sizeof(message),0);
        recv(forClientSockfd,receiveMessage,sizeof(receiveMessage),0);
        cout << receiveMessage << "\n";
        bzero(receiveMessage,sizeof(receiveMessage));
        bzero(message,sizeof(message));
        strcat(message, "Successfully remit the payment!");
        send(forClientSockfd,message,sizeof(message),0);
        bzero(message,sizeof(message));
    }
    return NULL;
}

int main(int argc , char *argv[])
{
	//initialize a socket
    int sockfd = 0;
    sockfd = socket(AF_INET , SOCK_STREAM , 0); // domain: AF_INET使用的是IPv4協定; type: SOCK_STREAM -> protocol為TCP; protocol: default 0

    if (sockfd == -1){
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
    info.sin_addr.s_addr = inet_addr(server_IP); // inet_addr()負責將字串型式的IP轉換為整數型式的IP。
    cout << "Please enter server's port number:";
    cin >> server_port;
    info.sin_port = htons(server_port);

    //Send a message to server
    char receiveMessage[LEN]; // buffer size
    
    // connect: get data from others
    int err = connect(sockfd, (struct sockaddr *)&info, sizeof(info));
    if(err == -1){
        cout << "Connection error. \n";
        return 0;
    }

    recv(sockfd,receiveMessage,sizeof(receiveMessage),0);
    cout << receiveMessage;
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

            send(sockfd,message,strlen(message),0);
            recv(sockfd,receiveMessage,sizeof(receiveMessage),0);
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
            send(sockfd,message,strlen(message),0);
            recv(sockfd,receiveMessage,sizeof(receiveMessage),0);
            cout << receiveMessage;
            if(receiveMessage != "220 AUTH_FAIL"){
                login(sockfd, portNum);
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

void login(int sockfd, char* portNum){
    // message sending between client 
    pthread_t pID;
	pthread_create(&pID, NULL, &sendsocket, portNum); 
	// pthread_join(pID, NULL); // 等，現在main thread 和 pthread 要同時進行，所以不用（但output會很亂）

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
            send(sockfd,message,strlen(message),0);
            recv(sockfd,receiveMessage,sizeof(receiveMessage),0);
            cout << receiveMessage;
            bzero(receiveMessage,sizeof(receiveMessage));
            bzero(message,sizeof(message));
        }
        
        //Exit
        else if(q == "e" || q == "E"){
            strcat(message, "Exit");
            send(sockfd,message,strlen(message),0);
            recv(sockfd,receiveMessage,sizeof(receiveMessage),0);
            cout << receiveMessage;
            close(sockfd);
            break;
        }

        // between client
        else if(q == "p" || q == "P"){
            cout << "This is a list of your account balance, number of users online and their information: \n";
            strcat(message, "List");
            send(sockfd,message,strlen(message),0);
            recv(sockfd,receiveMessage,sizeof(receiveMessage),0);
            cout << receiveMessage;
            
            char payee_IP[LEN];
            int payee_port = 0;
            char payee_name[IN_PUT];
            cout << "Please enter the payee's username: ";
            cin >> payee_name;

            char* pch = strstr(receiveMessage, payee_name);
            pch = strtok(pch, "#");
            pch = strtok(NULL, "#");
            strcat(payee_IP, pch);
            pch = strtok(NULL, "#");
            payee_port = atoi(pch);

            bzero(receiveMessage,sizeof(receiveMessage));
            bzero(message,sizeof(message));

            // initialize a socket
            int sockfd = 0;
            sockfd = socket(AF_INET , SOCK_STREAM , 0); // domain: AF_INET使用的是IPv4協定; type: SOCK_STREAM -> protocol為TCP; protocol: default 0

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
            recv(sockfd,receiveMessage,sizeof(receiveMessage),0);
            cout << receiveMessage << "\n";
            bzero(receiveMessage,sizeof(receiveMessage));

            char userName[IN_PUT];
            char payAmount[IN_PUT];
            cout << "Please enter your user name:";
            cin >> userName;
            cout << "Please enter the amount:";
            cin >> payAmount;
            strcat(message, userName);
            strcat(message, "#");
            strcat(message, payAmount);
            strcat(message, "#");
            strcat(message, payee_name);
            send(sockfd,message,strlen(message),0);
            recv(sockfd,receiveMessage,sizeof(receiveMessage),0);
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





