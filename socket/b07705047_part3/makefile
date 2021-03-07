all:client_s1 client_s2 server_s 

client_s1:client_ssl1.cpp
	g++ -pthread -o client_s1 client_ssl1.cpp -lcrypto -lssl
client_s2:client_ssl2.cpp
	g++ -pthread -o client_s2 client_ssl2.cpp -lcrypto -lssl
server_s:server_ssl.cpp
	g++ -pthread -o server_s server_ssl.cpp -lcrypto -lssl
clean:all
	rm all


