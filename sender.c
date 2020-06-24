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




void get_eth_index(int sock_r)
{
    memset(&ifreq_index,0,sizeof(ifreq_index));
    strncpy(ifreq_index.ifr_name,"wlp2s0",IFNAMSIZ-1);

    if((ioctl(sock_r,SIOCGIFINDEX,&ifreq_index))<0)
        printf("error in index ioctl reading");

    printf("index=%d\n",ifreq_index.ifr_ifindex);

}


bool strcmp_my(unsigned char *first,unsigned char *second,int upto) {
  for (int i=0;i<upto;i++){
    if (first[i] != second[i]){
      return 0;
    }
  }
  return 1;
}


void write_to_temp(int val){
  FILE *fp;
  int written;
  while(1){
 
  fp = fopen("temp", "w"); // write mode
 
  if (fp == NULL)
    {
      perror("Error while opening the file.\n");
      exit(EXIT_FAILURE);
    }
  written = fprintf(fp, "%d", val); 
  fclose(fp);
  if (written > 0){
    break;
    }
  }
  
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


int  CheckPacket(unsigned char * buffer,unsigned char *mac_addr) {
  struct ack_pac * packet = (struct ack_pac * )(buffer);
  
  
  if (packet->packet_indicator == 0x75 && packet->upo_type == 0x2 && strcmp_my((unsigned char *)packet->deth_head,mac_addr,6)) {

    printf("\n\n");

    printf("Got an ack packet:");
    
    for (int i=0; i<16;i++){
      printf("%x ",buffer[i]);
  }
    
    printf("\nPrinted it\n");
    
    return packet->pac_no; 
  }

  else {
    return -2;
  }
}



void Ack_Process() {
  
  unsigned  char * mac_addr;
  mac_addr = (unsigned char *)get_ether_addr("wlp2s0");
  int sending;
  
  int sock_r, saddr_len, buflen;
  struct sockaddr saddr;
  int yes,ack;
  unsigned char * buffer = (unsigned char * ) malloc(sizeof(struct ack_pac));
  memset(buffer, 0,sizeof(struct ack_pac));

  
  sock_r = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sock_r < 0) {
    printf("error in socket\n");
    exit(0);
  }
  
  if (setsockopt(sock_r, SOL_SOCKET, SO_REUSEADDR, & yes, sizeof yes) == -1) {
    perror("setsockopt");
    exit(0);
  }

  if (setsockopt(sock_r, SOL_SOCKET, SO_BINDTODEVICE, "wlp2s0", sizeof("wlp2s0")) == -1) {
    perror("SO_BINDTODEVICE");
    exit(0);
  }
  sending = get_number("temp");
  while(1) {
    
    saddr_len = sizeof saddr;
    buflen = recvfrom(sock_r, buffer, sizeof(struct ack_pac), 0, & saddr, (socklen_t * ) & saddr_len);
    
    if (buflen < 0) {
      printf("error in reading recvfrom function\n");
    }

    ack = CheckPacket(buffer,mac_addr);

    printf("\nAck Number  is %d\n", ack);
    
    if (ack > sending || ack == 0) {
      sending = ack;
      write_to_temp(sending);
    }
    
    if (sending==0) {
      exit(1);
    }
    /* delay(5); */

    
  }

}

void add_ether_packet_no(unsigned char * source ,unsigned char * destination,struct data_pac  *packet) {

  
  for (int i=0;i<6;i++) {
    packet->deth_head[i]=destination[i];
    packet->seth_head[i]=source[i];
  }
  packet->upo_type = 0x1;
  packet->packet_indicator = 0x75;  
}


int size_of_file_bytes(FILE *filename){
  int fsize;
  fseek(filename, 0, SEEK_END);
  fsize = ftell(filename);
  rewind(filename);
  return fsize;
}


int pack_next_data(struct data_pac * buffer,int sent_bytes, char * filename,short  to_be_sent) {

  
  FILE * opened_file = fopen(filename,"r");

  
  if (fseek(opened_file,sent_bytes,0) < 0){
    printf("Error While Seeking");
    exit(0);
  }

  if (feof(opened_file)){
    buffer->pac_no = 0;
    fclose(opened_file);
    return 0;
  }

unsigned  int bytes_read = fread(buffer->data , sizeof(char), sizeof(buffer->data), opened_file);
 memset((buffer->data) + bytes_read,0,sizeof(buffer->data) - bytes_read);
 if (bytes_read == sizeof(buffer->data)) {
   buffer->pac_no = to_be_sent;
   fclose(opened_file);
   return (int)bytes_read;
 }

 else if (bytes_read < sizeof(buffer->data) && bytes_read >0){
    buffer->pac_no = 0;
    fclose(opened_file);
    return (int)bytes_read;
 }
 printf("Error while reading");
 fclose(opened_file);
 exit(0);
}


int send_the_packet(struct  data_pac *sendbuffer) { 
  
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
  
  
  
  send_len = sendto(socket_discriptor , sendbuffer,1416,0,(const struct sockaddr*)&sadr_ll,sizeof(struct sockaddr_ll));
  if(send_len<0)
    {
      printf("error in sending....sendlen=%d....errno=%d\n",send_len,errno);
      return 0;
      
    }

  printf("\nSent packet is\n");
  
  unsigned char *see = (unsigned char *) sendbuffer;
 
  for (int i=0; i<1416;i++){
    printf("%x ",see[i]);
  }

  printf("\nFinshed printing\n");
  close(socket_discriptor);
  
 return 1;
}

void Packet_Process(char * filename) {
  
  struct data_pac  *buffer = (struct data_pac *) (malloc(sizeof(struct data_pac))) ;
  unsigned  char * mac_addr;
  unsigned char send_to_address[6] = {0xe4,0x46,0xda,0x4e,0xeb,0x67};
  mac_addr = (unsigned char *)get_ether_addr("wlp2s0");  
  add_ether_packet_no(mac_addr,send_to_address,buffer);
  
  
  FILE *opened_file;
  opened_file = fopen(filename, "rb");
  int size_of_file = size_of_file_bytes(opened_file);
  fclose(opened_file);
  int current_sending=1;
  int to_be_sent=get_number("temp");
  printf("File size is %d",size_of_file);
  int sent_bytes  = 0;
  
  
  int curr_sent_bytes = pack_next_data(buffer,sent_bytes,filename,to_be_sent);
  
  if (!(send_the_packet(buffer))){
    printf("Error in sending");
  }
  
  sent_bytes = curr_sent_bytes;
  
  
  while(1) {
    to_be_sent = get_number("temp");
    
    printf("\nTo be sent is %d\n",to_be_sent);
    
    if (to_be_sent==current_sending) {
      if (!(send_the_packet(buffer))){
	printf("Error in sending");
      }
    }

    else if (to_be_sent == (current_sending+1)) {
      
      curr_sent_bytes = pack_next_data(buffer,sent_bytes,filename,to_be_sent);
      
      if (curr_sent_bytes <0) {
	printf("Error while packing new packet");
	exit(0);
      }
      
      if (!(send_the_packet(buffer))){
	printf("Error in sending");
      }
      
      sent_bytes = sent_bytes + curr_sent_bytes;
      current_sending = to_be_sent;
    }
    
    
    else if (to_be_sent == 0) {
      printf("Sent Succesful");
      exit(1);
    }
    
    else {
      printf("Programmer is stupid. Forgot to right some edge case.");
      exit(0);
    }
     /* delay(5); */

  }
}





int main(int argc, char *argv []){
  
  FILE *temp,*filefd;
  
  filefd = check_file(argv[1]);       /* Checks if file to be sent is even present.If it is,gives file descriptor. Else exit. */

  
  temp = fopen("temp", "w");    /* Temporary File is for keeping tracks of reached packets. */
  fprintf(temp,"%d",1);
  fclose(temp);
  
  
  pid_t  pid;
  pid = fork();
  if (pid == 0) {
    Packet_Process(argv[1]);
  }
  else {
    Ack_Process();

  }
}
