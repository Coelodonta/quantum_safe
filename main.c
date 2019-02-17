#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "oqs.h"


#define LETS_USE_FRODO
#ifdef  LETS_USE_FRODO
/* Use Frodo (Learning With Errors) for the key exchange */
static int algorithm=OQS_KEX_alg_lwe_frodo;
/* Length of the seed */
static const size_t seedLen=16;
/* The seed (16 bytes) */
static const uint8_t *seed="qwertyuiopasdfgh";
/* Use the "recommended" parameter for >= 128 bits of security */
static const char *namedParms="recommended";
#endif

/* Host IP adress */
static const char *host= "127.0.0.1";
/* Port number */
static const int port=36000;
/* Some data buffers */
static char buffer[16384]={0};
static char plainText[16384]={0};
static char cipherText[16384]={0};
/* Prototypes */
int bob(OQS_KEX *kex);
int alice(OQS_KEX *kex);
int calculatePaddedLength(int len);

int main(int argc, char** argv){
    int rc=0;
    /* Initialize random numbers */
    OQS_RAND *rand = OQS_RAND_new(OQS_RAND_alg_urandom_chacha20);

    /* Initialize key exchange */
    OQS_KEX *kex = NULL;
    kex = OQS_KEX_new(rand, algorithm, seed, seedLen, namedParms);
    if(NULL==kex){
        return -1;
    }
    
    /* Check command line parms */
    if(argc<2){
	printf("Command line args:\n-C for client mode\n-S for server mode\n");
    }
    else if(0==strcmp(argv[1],"-C")){
	printf("starting client...\n");
	rc=alice(kex);
    }
    else if(0==strcmp(argv[1],"-S")){
	printf("starting server...\n\n");
        rc=bob(kex);
    }
    else{
	printf("Command line args:\n-C for client mode\n-S for server mode\n");
    }

    /* Clean up */
    OQS_RAND_free(rand);
    OQS_KEX_free(kex);
    return rc;	
}

/* This is for AES. A block has to be exactly 128 bits (16 bytes) */
int calculatePaddedLength(int len){
    if(0==len%16){
        return len;
    }
    int n=len/16;
    return 16*(n+1);
}

/* Set up and run chat program in client mode */
/* Client is Alice by convention */
int alice(OQS_KEX *kex){
    void *alicePrivate = NULL;   /* Alice's private key */
    uint8_t *aliceMsg = NULL; /* Alice's message */
    size_t aliceMsgLen = 0;  /* Alice's message length */
    uint8_t *aliceKey = NULL; /* Alice's final key */
    size_t aliceKeyLen = 0;  /* Alice's final key length */
    int rc=0;

    /* Open a socket */
    printf("Creating a socket\n");
    struct sockaddr_in address;
    int sock = 0, numChars;
    struct sockaddr_in serv_addr;
    if(0>(sock = socket(AF_INET, SOCK_STREAM, 0))){
        printf("Socket creation error \n");
        rc=-1;
        goto client_clean;
    }
    memset(&serv_addr, '0', sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
     
    if(0>=inet_pton(AF_INET,host, &serv_addr.sin_addr)){
        printf("Invalid address\n");
        rc=-1;
        goto client_clean;
    }
  
    if(connect(sock,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0){
        printf("Connect failed\n");
        rc=-1;
        goto client_clean;
    }

    /* BEGIN KEY EXCHANGE */
    /* Alice sends the Diffie Hellman initial message */
    printf("Starting key exchange\n");
    rc=OQS_KEX_alice_0(kex, &alicePrivate, &aliceMsg, &aliceMsgLen);
    if(OQS_SUCCESS!=rc) {
        fprintf(stderr,"ERROR: OQS_KEX_alice_0 failed!\n");
        goto client_clean;
    }
    OQS_print_part_hex_string("Alice initial message", aliceMsg, aliceMsgLen, 20);
    send(sock,aliceMsg,aliceMsgLen,0);

    /* Get response back from server */
    numChars = read( sock,buffer,sizeof buffer);
    
    /* process the response */
    uint8_t *bobMsg = NULL; // Bob's message
    size_t bobMsgLen = 0;  // Bob's message length
    bobMsg=buffer;
    bobMsgLen=numChars;
    
    rc = OQS_KEX_alice_1(kex, alicePrivate, bobMsg, bobMsgLen, &aliceKey,&aliceKeyLen);
    if(OQS_SUCCESS!=rc){
        printf("ERROR: OQS_KEX_alice_1 failed!\n");
        goto client_clean;
    }
    OQS_print_hex_string("Alice session key", aliceKey, aliceKeyLen);
    printf("Key exchange complete\n\n");
    /* END KEY EXCHANGE */

    /* Now start the chat */
    while(1){
        /* Get input from keyboard */
        memset(buffer,'\0',sizeof buffer);
        fgets(buffer,sizeof buffer,stdin);
        numChars=strlen(buffer);
        int len=calculatePaddedLength(numChars);
        
        /* Encrypt using session key */
        memset(cipherText,'\0',sizeof cipherText);
        OQS_AES128_ECB_enc(buffer,len,aliceKey,cipherText);

        /* Send encrypted message */
        send(sock,cipherText,len,0);
    
        /* Get response*/
        memset(buffer,'\0',sizeof buffer);
        numChars=read(sock,buffer,sizeof buffer);
        len=calculatePaddedLength(numChars);
        printf("\nEncrypted response from server:\n");
        for(int i=0;i<len;i++){
            printf("%2x",buffer[i]);
        }
        
        /* Decrypt using session key */
        memset(plainText,'\0',sizeof plainText);
        OQS_AES128_ECB_dec(buffer,len,aliceKey,plainText);
        printf("\nDecrypted response: %s\n",plainText);
    }
    
    
client_clean:
    OQS_MEM_secure_free(aliceMsg, aliceMsgLen);
    OQS_MEM_secure_free(aliceKey, aliceKeyLen);
    OQS_KEX_alice_priv_free(kex, alicePrivate);
    OQS_MEM_secure_free(bobMsg, bobMsgLen);
   
    return rc;
}

/* Set up and run chat program in server mode*/
/* Server is Bob by convention */
int bob(OQS_KEX *kex){
    uint8_t *bobMsg = NULL; // Bob's message
    size_t bobMsgLen = 0;  // Bob's message length
    uint8_t *bobKey = NULL; // Bob's final key
    size_t bobKeyLen = 0;  // Bob's final key length
    uint8_t *aliceMsg = NULL; // Alice's message
    size_t aliceMsgLen = 0;  // Alice's message length
    int rc=0;
    
    /* Set up a listen socket */
    int server_fd, new_socket, numChar;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
      
    /* Creating socket file descriptor */
    printf("Creating socket\n");
    if(0==(server_fd = socket(AF_INET, SOCK_STREAM, 0))){
        printf("socket failed\n");
        exit(EXIT_FAILURE);
    }
      
    /* Bind listening socket to the port */
    if(setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,&opt, sizeof(opt))){
        printf("setsockopt failed");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port=htons(port);    
    if (0>bind(server_fd, (struct sockaddr *)&address,sizeof(address))){
        printf("bind failed");
        exit(EXIT_FAILURE);
    }    
    
    /* Wait for a connection */
    printf("Listening\n");
    if (listen(server_fd, 3) < 0){
        printf("listen");
        exit(EXIT_FAILURE);
    }
    
    if(0>(new_socket=accept(server_fd, (struct sockaddr *)&address,(socklen_t*)&addrlen))){
        perror("accept");
        exit(EXIT_FAILURE);
    }    
    printf("Accepted incoming connection\n");
    
    /* BEGIN KEY EXCHANGE */
    /* Read the first incoming message */
    printf("Reading first message\n");
    memset(buffer,'\0',sizeof buffer);
    numChar=read(new_socket,buffer,sizeof buffer);
    
    /* Process first incoming message, which is part of key exchange */
    printf("Starting key exchange\n");
    aliceMsg=buffer;
    aliceMsgLen=numChar;
    rc=OQS_KEX_bob(kex, aliceMsg, aliceMsgLen, &bobMsg, &bobMsgLen, &bobKey, &bobKeyLen);
    if(OQS_SUCCESS!=rc) {
	fprintf(stderr,"ERROR: OQS_KEX_bob failed!\n");
        goto server_clean;
    }

    OQS_print_part_hex_string("Bob message", bobMsg, bobMsgLen, 20);
    OQS_print_hex_string("Bob session key", bobKey, bobKeyLen);
    
    /* Send the message to client */
    send(new_socket,bobMsg,bobMsgLen,0);
    printf("Key exchange complete\n\n");
    /* END KEY EXCHANGE*/

    while(1){
        /* Wait for next message */
        memset(buffer,'\0',sizeof buffer);
        numChar=read(new_socket,buffer,sizeof buffer);
        int len=calculatePaddedLength(numChar);
        printf("\nEncrypted message from client:\n");
        for(int i=0;i<len;i++){
            printf("%2x",buffer[i]);
        }
        
        /* Decrypt using session key */
        memset(plainText,'\0',sizeof plainText);
        OQS_AES128_ECB_dec(buffer,len,bobKey,plainText);
        printf("\nDecrypted message: %s\n",plainText);
        
        /* Compose a response */
        memset(buffer,'\0',sizeof buffer);
        sprintf(buffer,"Dear Alice,\nYou typed %s\n",plainText);
        numChar=strlen(buffer);
        len=calculatePaddedLength(numChar);
        
        /* Encrypt it using session key */
        memset(cipherText,'\0',sizeof cipherText);
        OQS_AES128_ECB_enc(buffer,len,bobKey,cipherText);

        /* Send to client */
        send(new_socket,cipherText,len,0);
    }
server_clean:    
    OQS_MEM_secure_free(bobMsg, bobMsgLen);
    OQS_MEM_secure_free(bobKey, bobKeyLen);
    OQS_MEM_secure_free(aliceMsg, aliceMsgLen);

    return rc;
}
