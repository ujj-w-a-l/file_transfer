#include <stdio.h>
#include  <sys/types.h>
#include <unistd.h>

#include <string.h>
#include <stdbool.h>

#include <stdlib.h>

#include <arpa/inet.h>
#include<errno.h>
#include <linux/if_packet.h>


#include <time.h>

#include <sys/stat.h>
#include <sys/wait.h>
#include<sys/ioctl.h>
#include <net/if.h>
#include<netinet/if_ether.h>
#include <net/ethernet.h> 
/*                                                                ___________________                                                                       */
/*                                                               | Packet Types |                                                                        */
/*                                                               ------------------------                                                                        */
/*                                              6 Bytes               6 Bytes       1 Byte         2 Bytes         1000 Bytes             */
/*             Data Packet : |Destination Mac|Source Mac|   0x1      |Packet No   |      Data       |            */
             
/*                                              6 Bytes               6 Bytes       1 Byte         2 Bytes                                       */
/*             ACK Packet : |Destination Mac  |Source Mac|   0x2      |Packet No   |                                   */




struct ifreq ifreq_mac;
struct ifreq ifreq_index;

struct data_pac
{
  unsigned char deth_head[6];
  unsigned char seth_head[6];
  unsigned char packet_indicator;
  unsigned char upo_type;
  short pac_no;
  unsigned char  data[1400];  
};

struct ack_pac
{
  unsigned char  deth_head[6];
  unsigned char  seth_head[6];
  unsigned char packet_indicator;
  unsigned char upo_type;
  short pac_no;
};


void delay(int number_of_seconds)
{
  // Converting time into milli_seconds
  int milli_seconds = 1000 * number_of_seconds;
  
  // Stroing start time
  clock_t start_time = clock();
  
    // looping till required time is not acheived
  while (clock() < start_time + milli_seconds);
}
 



int file_exist (char *filename)
{
  struct stat buffer;   
  return (stat (filename, &buffer) == 0);
}



void get_eth_index(int sock_r)
{
  memset(&ifreq_index,0,sizeof(ifreq_index));
  strncpy(ifreq_index.ifr_name,"wlan0",IFNAMSIZ-1);

  if((ioctl(sock_r,SIOCGIFINDEX,&ifreq_index))<0)
    printf("error in index ioctl reading");

}


bool strcmp_my(unsigned char *first,unsigned char *second,int upto) {
  for (int i=0;i<upto;i++){
    if (first[i] != second[i]){
      return 0;
    }
  }
  return 1;
}




FILE * check_file(char * file_path){
  FILE *fptr = fopen(file_path, "r") ;
  if (fptr ==0 )
    {
 
      perror("File to be sent not found");
      exit(0);
    }
  fclose(fptr);
  return fptr;
}


int get_number(char  *temp) {
  FILE *fp;
  int read, val;
  while(1) {
    fp = fopen(temp, "r"); // read mode
 
  if (fp == NULL)
    {
      perror("Error while opening the file in get number.\n");
      exit(EXIT_FAILURE);
    }
  
  fseek(fp, 0, SEEK_END);
  long fsize = ftell(fp);
  fseek(fp, 0, SEEK_SET);  //same as rewind(f);
  
  char *string = malloc(fsize + 1);
  read = fread(string, fsize, 1, fp);  
  fclose(fp);
  if (read > 0){
    val = (atoi(string));
    break;
  }
  }
  return  val;
}
  


char *  get_ether_addr(char * interface_name) {

  memset(&ifreq_mac,0,sizeof(ifreq_mac));
  strncpy(ifreq_mac.ifr_name,interface_name,IFNAMSIZ-1);

  int socket_fd;
  int yes=1;

  socket_fd = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));


  if(socket_fd== -1) {
    fprintf(stderr, "Socket failure!!\n");
    exit(0);
  }
  
  if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
    perror("setsockopt");
    exit(0);
  }

  
  
  if((ioctl(socket_fd,SIOCGIFHWADDR,&ifreq_mac))<0) {
    printf("error in SIOCGIFHWADDR ioctl reading");
    exit(0);
  }
  printf("Mac= %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",(unsigned char)(ifreq_mac.ifr_hwaddr.sa_data[0]),(unsigned char)(ifreq_mac.ifr_hwaddr.sa_data[1]),(unsigned char)(ifreq_mac.ifr_hwaddr.sa_data[2]),(unsigned char)(ifreq_mac.ifr_hwaddr.sa_data[3]),(unsigned char)(ifreq_mac.ifr_hwaddr.sa_data[4]),(unsigned char)(ifreq_mac.ifr_hwaddr.sa_data[5]));


  return ifreq_mac.ifr_hwaddr.sa_data;

}


short  CheckPacket_Type(unsigned char * buffer,unsigned char *mac_addr) {
  struct ack_pac * packet = (struct ack_pac * )(buffer);

  
  /* for (int i=0; i<1416;i++){ */
  /*     printf("%x ",buffer[i]); */
  /* } */
  
  
  
  if (strcmp_my((unsigned char *)packet->deth_head,mac_addr,6) && packet->packet_indicator == 0x75 ) {
    return packet->upo_type; 
  }

  else{
    return -1;
  }
}


int treat_data_packet(unsigned char *buffer){

  /* printf("\n\n\n\n\n\n\n Got data packet \n\n\n\n\n\n\n"); */
  
  struct data_pac * packet = (struct data_pac *) buffer;  
  FILE *infile;
  struct data_pac file_data;
     
  infile = fopen ("data", "r");
  if (infile == NULL)
    {
      fprintf(stderr, "\nError opening file\n");
      exit (1);
    }

  int read_values = fread(&file_data, sizeof(struct data_pac), 1, infile);

  /* printf("Packet data no is %d and packet no. is %d", file_data.pac_no, packet->pac_no); */

  if (read_values == 0){
    FILE *fp_data_first, *fp_sending_first;
    fp_data_first = fopen("data", "w"); // write mode
    
    if (fp_data_first == NULL)
      {
	perror("Error while opening the file.\n");
	exit(EXIT_FAILURE);
      }
    fwrite (packet, sizeof(struct data_pac), 1, fp_data_first);
    fclose(fp_data_first);
    
    fp_sending_first = fopen("sending", "w");
    if (fp_sending_first == NULL)
      {
	perror("Error while opening the file.\n");
	exit(EXIT_FAILURE);
      }
    fprintf(fp_sending_first, "%d", packet->pac_no); 
    fclose(fp_sending_first);
    return 1;
  }
  
  else if (file_data.pac_no == packet->pac_no) {
    printf("Data already sending\n");
    return 1;
  }
  
  else if (packet->pac_no == file_data.pac_no+1) {
    FILE *fp_data, *fp_sending;
    fp_data = fopen("data", "w"); // write mode
    
    if (fp_data == NULL)
      {
	perror("Error while opening the file.\n");
	exit(EXIT_FAILURE);
      }
    fwrite (packet, sizeof(struct data_pac), 1, fp_data);
    fclose(fp_data);
    
    fp_sending = fopen("sending", "w");
    if (fp_sending == NULL)
      {
	perror("Error while opening the file.\n");
	exit(EXIT_FAILURE);
      }
    fprintf(fp_sending, "%d", packet->pac_no); 
    fclose(fp_sending);
    return 1;
  }

  else if (packet->pac_no == 0) {
    FILE *fp_data, *fp_sending;
    fp_data = fopen("data", "w"); // write mode
    
    if (fp_data == NULL)
      {
	perror("Error while opening the file.\n");
	exit(EXIT_FAILURE);
      }
    fwrite (packet, sizeof(struct data_pac), 1, fp_data);
    fclose(fp_data);
    
    fp_sending = fopen("sending", "w");
    if (fp_sending == NULL)
      {
	perror("Error while opening the file.\n");
	exit(EXIT_FAILURE);
      }
    fprintf(fp_sending, "%d", packet->pac_no); 
    fclose(fp_sending);
    return 1;
  }

  
  else {
    printf("Some problem in algorithm");
    return 0;
  }
}

int treat_ack_packet(unsigned char *buffer) {

  printf("\n\n\n\n\n\n\n Got ack packet \n\n\n\n\n\n\n");
  
  struct ack_pac * packet = (struct ack_pac *) buffer;

  printf("\n Packet Number %d to be sent now\n", packet->pac_no);

  
  
  FILE *infile;
  char in_char;
  short number;
  

  number = get_number("to_be_sent");

  printf("\n\n\n\n\n Sending ack is %d and received is %d \n\n\n", number, packet->pac_no);

  
  if (number == packet->pac_no) {
    printf("Ack already sending");
    return 1;
  }
  
  else if (packet->pac_no == number+1) {
    FILE *fp_sent;
    fp_sent = fopen("to_be_sent", "w"); // write mode
    
    if (fp_sent == NULL)
      {
	perror("Error while opening the file.\n");
	exit(EXIT_FAILURE);
      }
    fprintf(fp_sent,"%d",packet->pac_no);
    fclose(fp_sent);
    return 1;
  }

  else if (packet->pac_no==0 ||packet->pac_no==2 ){
    FILE *fp_sent;
    fp_sent = fopen("to_be_sent", "w"); // write mode
    
    if (fp_sent == NULL)
      {
	perror("Error while opening the file.\n");
	exit(EXIT_FAILURE);
      }
    fprintf(fp_sent,"%d",packet->pac_no);
    fclose(fp_sent);
    return 1;
  }

  
  else  {
    printf("\n Some problem in ack algorithm \n");
    return 0;
  }
}




void Ack_Process()  {
  
  unsigned  char * mac_addr;
  mac_addr = (unsigned char *)get_ether_addr("wlan0");
  int sending,sent;

  int sock_r, saddr_len, buflen;
  struct sockaddr saddr;
  int yes,type;
  unsigned char * buffer = (unsigned char * ) malloc(sizeof(struct data_pac));
  memset(buffer, 0,sizeof(struct data_pac));

  
  sock_r = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sock_r < 0) {
    printf("error in socket\n");
    exit(0);
  }
  
  if (setsockopt(sock_r, SOL_SOCKET, SO_REUSEADDR, & yes, sizeof yes) == -1) {
    perror("setsockopt");
    exit(0);
  }

  if (setsockopt(sock_r, SOL_SOCKET, SO_BINDTODEVICE, "wlan0", sizeof("wlan0")) == -1) {
    perror("SO_BINDTODEVICE");
    exit(0);
  }
  
  sending = get_number("sending");
  sent = get_number("to_be_sent");
  
  while(1) {
    
    saddr_len = sizeof saddr;
    buflen = recvfrom(sock_r, buffer, sizeof(struct data_pac), 0, & saddr, (socklen_t * ) & saddr_len);
    
    if (buflen < 0) {
      printf("error in reading recvfrom function\n");
    }

    printf("\nRead length : %d\n", buflen);
    type = CheckPacket_Type(buffer,mac_addr);
    printf("\nType is %d\n", type);
    
    
    if (type == 0x1) {
      if(!(treat_data_packet(buffer))) {
	printf("Error While treating data packet");
	exit(0);
      }
    }

    else if (type == 0x2) {
      if (!(treat_ack_packet(buffer))) {
	printf("Error While treating ack packet");
	exit(0);
      }
    }
    else {

      printf("\n\nOther type of packet received \n\n");
      
    }
         /* delay(5) ; */

    
  }
  
}

void add_ether_packet_no(unsigned char * source ,unsigned char * destination,struct data_pac  *packet, short packet_no) {

  for (int i=0;i<6;i++) {
    packet->deth_head[i]=destination[i];
    packet->seth_head[i]=source[i];
  }
  packet->upo_type = 0x1;
  packet->packet_indicator=0x75;
  packet->pac_no = packet_no;
  
}


int size_of_file_bytes(FILE *filename){
  int fsize;
  fseek(filename, 0, SEEK_END);
  fsize = ftell(filename);
  rewind(filename);
  return fsize;
}



void add_ack_packet_no (unsigned char * source ,unsigned char * destination, struct ack_pac *ack_buffer,int packet_no) {
  for (int i=0;i<6;i++) {
    ack_buffer->deth_head[i]=destination[i];
    ack_buffer->seth_head[i]=source[i];
  }
  ack_buffer->packet_indicator = 0x75;
  ack_buffer->upo_type = 0x2;
  ack_buffer->pac_no = packet_no;

}

int send_the_packet_ack(struct  ack_pac *sendbuffer) { 

  if ( sendbuffer->pac_no == -1 ){
    return 1;
  }
 
  int yes=1;
  
  int socket_discriptor = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));

  if(socket_discriptor == -1) {
    fprintf(stderr, "Socket failure!!\n");
    exit(1);
  }
  
  if (setsockopt(socket_discriptor, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
    perror("setsockopt");
    exit(1);
  }

  get_eth_index(socket_discriptor);

  struct sockaddr_ll sadr_ll;
  sadr_ll.sll_ifindex = ifreq_index.ifr_ifindex;
  sadr_ll.sll_halen   = ETH_ALEN;
  sadr_ll.sll_addr[0]  = sendbuffer->deth_head[0];
  sadr_ll.sll_addr[1]  = sendbuffer->deth_head[1];
  sadr_ll.sll_addr[2]  = sendbuffer->deth_head[2];
  sadr_ll.sll_addr[3]  = sendbuffer->deth_head[3];
  sadr_ll.sll_addr[4]  = sendbuffer->deth_head[4];
  sadr_ll.sll_addr[5]  = sendbuffer->deth_head[5];

  int send_len;
      
  send_len = sendto(socket_discriptor , sendbuffer,sizeof(struct ack_pac),0,(const struct sockaddr*)&sadr_ll,sizeof(struct sockaddr_ll));
  if(send_len<0)
    {
      printf("error in sending....sendlen=%d....errno=%d\n",send_len,errno);
      return 0;
      
    }

    unsigned char *see = (unsigned char *) sendbuffer;

  /* printf("\n\nSent ack :\n"); */
  /* for (int i=0; i<16;i++){ */
  /*   printf("%x ",see[i]); */
  /* } */
  
  close(socket_discriptor);

  return 1;
}


int pack_next_data(struct data_pac * buffer,int sending) {

  if (sending == -1) {
    return 1;
  }

  FILE *infile;
  infile = fopen ("data", "r");
  if (infile == NULL)
    {
      printf("Error in opening file");
      fprintf(stderr, "\nError opening file\n");
      exit (0);
    }
  
  struct data_pac buffer_read;
  fread(&buffer_read, sizeof(struct data_pac), 1, infile);
   printf("\nHere\n");

   unsigned char *see = (unsigned char *) &buffer_read;

   printf("\n\nRead Packet :\n");
     
   for (int i=0; i<1416;i++){
       printf("%x ",see[i]);
   }
   printf("\n\n Packet Finish\n");
  fclose(infile);
  
  if (buffer_read.pac_no == sending ) {
    buffer->pac_no = sending;
    for (int i=0;i<1400;i++) {
      buffer->data[i]=buffer_read.data[i];
    }

    printf("\n\n\n\nRead from data file is %d and sending is %d\n\n\n", buffer_read.pac_no, sending);

    printf("So Buffer to be sent is: \n");

    see = (unsigned char *)buffer;
    
    for (int i=0; i<1416;i++){
      printf("%x ",see[i]);
   }
    return 1;
  }
  
  else {

    printf("\n\n\nHere1\n\n\n\n");
    
    FILE *temp;
    temp = fopen ("sending", "w");
    if (temp == NULL)
      {

	printf("\n\n\nHere2\n\n\n\n");

	fprintf(stderr, "\nError opening file in packing\n");
	exit (1);
      }
    fprintf(temp,"%d", buffer_read.pac_no);
    printf("\n\n\nHere2\n\n\n\n");
    
    fclose(temp);
    return 1;
  }
  
  printf("\n\n\nHere3\n\n\n\n");

  
    return 0;
}

 






int send_the_packet(struct  data_pac *sendbuffer) { 

  if (sendbuffer->pac_no == -1 ){

    printf("\n Not really sending \n");

    return 1;
  }
  
  int yes=1;
  
  int socket_discriptor = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));

  if(socket_discriptor == -1) {
    fprintf(stderr, "Socket failure!!\n");
    exit(1);
  }
  
  if (setsockopt(socket_discriptor, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
    perror("setsockopt");
    exit(1);
  }

  get_eth_index(socket_discriptor);

  struct sockaddr_ll sadr_ll;
  sadr_ll.sll_ifindex = ifreq_index.ifr_ifindex;
  sadr_ll.sll_halen   = ETH_ALEN;
  sadr_ll.sll_addr[0]  = sendbuffer->deth_head[0];
  sadr_ll.sll_addr[1]  = sendbuffer->deth_head[1];
  sadr_ll.sll_addr[2]  = sendbuffer->deth_head[2];
  sadr_ll.sll_addr[3]  = sendbuffer->deth_head[3];
  sadr_ll.sll_addr[4]  = sendbuffer->deth_head[4];
  sadr_ll.sll_addr[5]  = sendbuffer->deth_head[5];

  int send_len;
  
  send_len = sendto(socket_discriptor , sendbuffer,sizeof(struct data_pac ),0,(const struct sockaddr*)&sadr_ll,sizeof(struct sockaddr_ll));
  if(send_len<0)
    {
      printf("error in sending....sendlen=%d....errno=%d\n",send_len,errno);
      return 0;
      
    }

  unsigned char *see = (unsigned char *) sendbuffer;

  /* printf("\n\nSent Packet:\n"); */
  
  /* for (int i=0; i<1416;i++){ */
  /*   printf("%x ",see[i]); */
  /* } */


  
  close(socket_discriptor);

  return 1;
}



void Packet_Process() {

  struct data_pac  *buffer = (struct data_pac *) (malloc(sizeof(struct data_pac))) ;
  struct ack_pac *ack_buffer = (struct ack_pac *) (malloc(sizeof(struct ack_pac))) ;
  
  
  unsigned  char * mac_addr;
  unsigned char send_to_address[6] = {0x70,0x18, 0x8b, 0xa6, 0x9b, 0xcf};
  unsigned char send_to_address_ack[6] = {0xa0,0xc5,0x89,0x85,0x3f,0x90};
  
  
  int sending = -1;
  int sent = -1;
  int resume_sending = get_number("sending");
  int resume_sent = get_number("to_be_sent");

  if (!(sending == resume_sending)) {
    sending = resume_sending;
  }
  
  if (!(sent == resume_sent)) {
    sent = resume_sent;
  }

  mac_addr = (unsigned char *)get_ether_addr("wlan0");

  printf("Adding header to ack\n");
  add_ack_packet_no(mac_addr,send_to_address_ack,ack_buffer,sent);

  unsigned char *see = (unsigned char *)ack_buffer;
  
  for(int i = 0;i < 16;i++ ){
    printf("%x ", see[i]);
  }
  printf("Ack  Header added: ");
  
  
  printf("Adding ether to ack\n");
  add_ether_packet_no(mac_addr,send_to_address,buffer,sending);

  see = (unsigned char *) buffer;
  
  for(int i = 0 ;i < 1416;i++){
    printf("%x", see[i]);
  }
  printf("Data packet with header.\n ");

  
  if (!(pack_next_data(buffer,sending))){
    printf("Error in packing data First Packet.");
    exit(EXIT_FAILURE);
  }
  
  if (!(send_the_packet_ack(ack_buffer))){
    printf("Error in sending ACK");
  }

  if (!(send_the_packet(buffer))){
    printf("Error in sending");
  }

 
  while(1) {  
    int current_sending =  get_number("sending");
    int current_sent = get_number("to_be_sent");

    printf("\n\nsending %d \n", sending);
    
    if(current_sending == sending) {
      if (!(send_the_packet(buffer))){
	printf("\nError in sending\n");
      }
    }

    else if (current_sending == 1 && sending == -1){
      printf("First packet\n");
      if (! pack_next_data(buffer,current_sending)){
	printf("\n\n\n\n Error in packing First packet\n\n\n");
      }
      if (!(send_the_packet(buffer))){
	printf("Error in sending");
      }
      sending = current_sending;
    }
    
    else if (current_sending == sending+1) {
      if ( !pack_next_data(buffer,current_sending)){
	printf("\n\n\n\n\nError in packing middle packet \n\n\n\n");
      }
      if (!(send_the_packet(buffer))){
	printf("Error in sending");
      }
      sending = current_sending;
    }

    else if (current_sending == 0){
      
      printf("Last Packet Sent");
      
      if ( !pack_next_data(buffer,current_sending)){
	printf("\n\n\n\n\nError in packing middle packet \n\n\n\n");
      }
      if (!(send_the_packet(buffer))){
	printf("Error in sending");
      }
      sending = current_sending;
    }
    
    else {
      printf("Programmer is stupid. Forgot to right some edge case.");
      exit(0);
    }
    
    
    if(current_sent == sent) {
      if (!(send_the_packet_ack(ack_buffer))){
	printf("Error in sending");
      }
      /* printf("\nSendig Same ack:%d Which is :", sent); */
      
      unsigned char *see = (unsigned char *) ack_buffer;
      
      for (int i=0; i<16;i++){
	printf("%x ",see[i]);
      }

      printf("\nSent ack\n");

      
    }
  
    else if (current_sent == sent+1) {
      add_ack_packet_no(mac_addr, send_to_address_ack,ack_buffer,current_sent);

	printf("\nPacking Ack with :%d\n", current_sent);
	
      if (!(send_the_packet_ack(ack_buffer))){
	printf("Error in sending");
      }
      sent = current_sent;
    }
    

    else if (current_sent == 0 || current_sent == 2)  {
      add_ack_packet_no(mac_addr, send_to_address_ack,ack_buffer,current_sent);
    if (!(send_the_packet_ack(ack_buffer))){
      printf("Error in sending");
    }
    sent = current_sent;
     
    }

    else {
      printf ("\n\n\n\n\n\n\n\n\n\n\n\n Programmer is stupid. Forgot to right some edge case.\n\n\n\n\n\n\n\n\n\n\n\n");
      exit(0);
    }

    /* delay(5); */
    
  }
}



int main() {
  
  FILE *temp;

  if (!(file_exist("data") && file_exist("sending") && file_exist("to_be_sent")) ) {
    temp = fopen("data", "w"); 
    fclose(temp);

    temp = fopen("sending", "w"); 
    fprintf(temp,"-1");
    fclose(temp);

    temp = fopen("to_be_sent", "w"); 
    fprintf(temp,"-1");
    fclose(temp);
  }
  
  pid_t  pid;
  pid = fork();
  if (pid == 0) {
    Packet_Process();
  }
  else {
    Ack_Process();
  }
}
