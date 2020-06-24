 #include <stdio.h>
#include  <sys/types.h>

#include <unistd.h>

#include <string.h>
#include <stdbool.h>

#include <stdlib.h>

#include <arpa/inet.h>

#include<errno.h>
#include <linux/if_packet.h>


#include <sys/wait.h>
#include <time.h>
#include<sys/ioctl.h>
#include <net/if.h>
#include<netinet/if_ether.h>
#include <net/ethernet.h>

#include <sys/stat.h>

/*                                                                ___________________                                                                       */
/*                                                               | Packet Types |                                                                        */
/*                                                               ------------------------                                                                        */
/*                                              6 Bytes               6 Bytes       1 Byte         2 Bytes         1400 Bytes             */
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



void get_eth_index(int sock_r)
{
  memset(&ifreq_index,0,sizeof(ifreq_index));
  strncpy(ifreq_index.ifr_name,"wlo1",IFNAMSIZ-1);

  if((ioctl(sock_r,SIOCGIFINDEX,&ifreq_index))<0)
    printf("error in index ioctl reading");
}


int file_exist (char *filename)
{
  struct stat buffer;   
  return (stat (filename, &buffer) == 0);
}


bool strcmp_my(unsigned char *first,unsigned char *second,int upto) {
  for (int i=0;i<upto;i++){
    if (first[i] != second[i]){
      return 0;
    }
  }
  return 1;
}


void write_no_to_file(char *file, short  val){

  FILE *fp;
      fp = fopen(file, "w"); // write mode
      
      if (fp == NULL)
	{
	  perror("Error while opening the file.\n");
	  exit(EXIT_FAILURE);
	}
      fprintf(fp, "%d", val); 
      fclose(fp);    
}


void write_data_to_file(unsigned char * buffer, int bytes) {

  struct data_pac * packet = (struct data_pac *) buffer;
  
  FILE *fp;
  fp = fopen("receive_file", "a");
  
  if (fp == NULL)
    {
      perror("Error while opening the file.\n");
      exit(EXIT_FAILURE);
    }
  
  fwrite(&packet->data , bytes , sizeof(char), fp);
  fclose(fp); 
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
  int read_chars = 0;
  char *string;
  while(!(read_chars)) {
  fp = fopen(temp, "r"); // read mode
 
  if (fp == NULL)
    {
      perror("Error while opening the file.\n");
      exit(EXIT_FAILURE);
    }
  
  fseek(fp, 0, SEEK_END);
  long fsize = ftell(fp);
  fseek(fp, 0, SEEK_SET);  //same as rewind(f);

  string = malloc(fsize + 1);
  
  read_chars = fread(string, fsize, 1, fp);
  fclose(fp);
  }
  
  return (atoi(string));
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


int  CheckPacket(unsigned char * buffer,unsigned char *mac_addr) {
  struct ack_pac * packet = (struct ack_pac * )(buffer);

  if (packet->packet_indicator == 0x75 && packet->upo_type == 0x1 && strcmp_my((unsigned char *)packet->deth_head,mac_addr,6)) {

  
    
    return packet->pac_no; 
  }

  else{
    return -2;
  }
}



void packet_save_Process() {  
  unsigned  char * mac_addr;
  mac_addr = (unsigned char *)get_ether_addr("wlo1");
  int to_be_received;
  
  int sock_r, saddr_len, buflen;
  struct sockaddr saddr;
  int yes,ack;
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

  if (setsockopt(sock_r, SOL_SOCKET, SO_BINDTODEVICE, "wlo1", sizeof("wlo1")) == -1) {
    perror("SO_BINDTODEVICE");
    exit(0);
  }
  
  while(1) {
    
    to_be_received = get_number("to_be_received");
    
    saddr_len = sizeof saddr;
    buflen = recvfrom(sock_r, buffer, 1416, 0, & saddr, (socklen_t * ) & saddr_len);
    
    
    if (buflen < 0) {
      printf("error in reading recvfrom function\n");
    }

    
    printf("\n\n");
        
    ack = CheckPacket(buffer,mac_addr);

    printf("Check packet gave %d", ack);
    
    if (ack == to_be_received) {
      
      write_data_to_file(buffer,buflen-16);
      write_no_to_file("to_be_received", to_be_received + 1);
    }
    
    else if (ack == 0) {
      write_data_to_file(buffer,buflen-16);
      write_no_to_file("to_be_received", 0);
      printf("Last packet Received");
      break;
    }

    else if (ack == 1 && to_be_received != ack + 1) {
      printf("Some data to_be_received");
      write_data_to_file(buffer, buflen - 16);
      write_no_to_file("to_be_received", ack + 1);
      printf("First packet Received");
    }

    else if (ack == to_be_received - 1){
      printf("already added");
    }

    else if (ack == -2) {
      printf("\nOther packet\n");
    }

    else{
      printf("Programmer is stupid can't find edge cases");
    }

    /* delay(3); */
    
  }
  }




void add_ether_packet_no(unsigned char * source ,unsigned char * destination,struct ack_pac  *packet,short packet_no) {

  for (int i=0;i<6;i++) {
    packet->deth_head[i]=destination[i];
    packet->seth_head[i]=source[i];
  }

  packet->upo_type = 0x2;
  packet->pac_no = packet_no;
  packet->packet_indicator = 0x75;
  
}


int send_the_packet_ack(struct  ack_pac *sendbuffer) { 
  
  if ( sendbuffer->pac_no == -1 ){

    printf("Not really ack sent");
    
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


  unsigned char *see = (unsigned char *) sendbuffer;

  
  send_len = sendto(socket_discriptor , sendbuffer,sizeof(struct ack_pac),0,(const struct sockaddr*)&sadr_ll,sizeof(struct sockaddr_ll));
  if(send_len<0)
    {
      printf("error in sending....sendlen=%d....errno=%d\n",send_len,errno);
      return 0;
      
    }

  

  for (int i=0; i<16;i++){
    printf("%x ",see[i]);
  }
  
  close(socket_discriptor);
  return 1;
}


void ack_send_Process()  {

  struct ack_pac  *buffer = (struct ack_pac *) (malloc(sizeof(struct ack_pac))) ;
  unsigned  char * mac_addr;
  unsigned char send_to_address[6] = {0xe4,0x46,0xda,0x4e,0xeb,0x67};
  mac_addr = (unsigned char *)get_ether_addr("wlo1");  
  add_ether_packet_no(mac_addr,send_to_address,buffer,-1);
  
  
  
  if (!(send_the_packet_ack(buffer))){
    printf("Error in sending");
  }
  
  
  int current_sending=-1;
  int to_be_sent;

  while(1) {

    to_be_sent = get_number("to_be_received");

    printf("\nRequesting for %d\n", to_be_sent);

    
    if (to_be_sent == current_sending) {
      if (!(send_the_packet_ack(buffer))){
	printf("Error in sending");
      }
    }
    
    else if ( to_be_sent == current_sending+1 || to_be_sent == 0 || to_be_sent == 2) {
      
      buffer->pac_no=to_be_sent;
      if (!(send_the_packet_ack(buffer))){
	printf("Error in sending");
      }
      current_sending = to_be_sent;
    }
    else {
      printf("Programmer is stupid. Forgot to right some edge case in ack process");
      exit(0);
    }
     /* delay(3) ; */
  }
}


int main(int argc, char *argv []){
  FILE * fp_sending, *file;
  
  fp_sending = fopen("to_be_received", "w");
  if (fp_sending == NULL)
    {
      perror("Error while opening the file.\n");
      exit(EXIT_FAILURE);
    }
  fprintf(fp_sending, "%d", -1); 
  fclose(fp_sending);
  
  
  file = fopen("receive_file", "w");
  if (file == NULL)
    {
      perror("Error while opening the file.\n");
      exit(EXIT_FAILURE);
    }
  fclose(file);

  
  pid_t  pid;
  pid = fork();
  if (pid == 0) {
    ack_send_Process();
  }
  else {
    packet_save_Process();
  }
}
