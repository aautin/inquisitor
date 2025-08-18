gcc src/*.c -o inquisitor -lpcap -Iinc

./inquisitor $CLIENT_IP $CLIENT_MAC $SERVER_IP $SERVER_MAC