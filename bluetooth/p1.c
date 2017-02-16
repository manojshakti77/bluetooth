#include"p1.h"
uint8_t hci_send_cmd(unsigned short int opcode)
{
	int sfd,retval;
	int dev_id;
	
}
int hci_rec_event(unsigned char *buf);
int main(void)
{
	unsigned short int ogf,ocf,opcode;
	int sfd,retval;
	char buf[260];
	sockaddr_hci a;
	hci_command_hdr h;
	hci_event_hdr event_hdr;
	hci_set_le_adv_data le_adv_data;
	hci_set_event_mask set_event_mask;
	struct hci_filter nf;
	unsigned char *ptr;
	ogf = CONTROL_BASEBAND;
	ocf = HCI_RESET_COMMAND;
	opcode=(unsigned short int)((ocf & 0x03ff)|(ogf << 10));;
	memset(&h, 0, sizeof(h));
	h.pkt_type=0x01;
	h.opcode_lsb = (unsigned char)(opcode >>8);
	h.opcode_msb = (unsigned char)(opcode & 0x00ff);
	h.plen=0x00;
	
	sfd=socket(AF_BLUETOOTH,SOCK_RAW,BTPROTO_HCI);
	if(sfd < 0)
	{
		perror("sfd");
		return 0;
	}
	memset(&a, 0, sizeof(a));
	a.hci_family=AF_BLUETOOTH;
	a.hci_dev=0;
        if (bind(sfd, (struct sockaddr *) &a, sizeof(a)) < 0)
	{
		perror("bind");
		return 0;
	}
	/* Linux related(Setting the filter characterstics */
	hci_filter_clear(&nf);
        hci_filter_set_ptype(HCI_EVENT_PKT,  &nf);
        hci_filter_set_event(EVT_CMD_STATUS, &nf);
        hci_filter_set_event(EVT_CMD_COMPLETE, &nf);
        hci_filter_set_event(EVT_LE_META_EVENT, &nf); 
        //hci_filter_set_event(EVT_CMD_STATUS, &nf);
        hci_filter_set_opcode(opcode, &nf); 

	if (setsockopt(sfd,SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0)
	return 0;

	/*Writing to the HCI*/
	retval=write(sfd,&h,sizeof(h));
	perror("write");
	if(retval <0)
		return 0;
	/*Reading from HCI*/
	while ((retval = read(sfd, buf, sizeof(buf))) < 0) {
                        if (errno == EAGAIN || errno == EINTR)
                                continue;
                        break;
                }

	unsigned char num_cmds;
	hci_rec_event(buf);

	printf("EVENT_MASK\n");

	ogf = CONTROL_BASEBAND;
	ocf = 0x0001;
	opcode=(unsigned short int)((ocf & 0x03ff)|(ogf << 10));;
	set_event_mask.pkt_type=0x01;
	set_event_mask.opcode_lsb = (unsigned char)(opcode >>8);
	set_event_mask.opcode_msb = (unsigned char)(opcode & 0x00ff);
	set_event_mask.plen=0x08;
	set_event_mask.set_event_mask_data[0] = 0x00;
	set_event_mask.set_event_mask_data[1] = 0x00;
	set_event_mask.set_event_mask_data[2] = 0x00;
	set_event_mask.set_event_mask_data[3] = 0x00;
	set_event_mask.set_event_mask_data[4] = 0x00;
	set_event_mask.set_event_mask_data[5] = 0x00;
	set_event_mask.set_event_mask_data[6] = 0x00;
	set_event_mask.set_event_mask_data[7] = 0x00;

	retval=write(sfd,&h,sizeof(h));
	perror("write");
	if(retval <0)
		return 0;
	/*Reading from HCI*/
	while ((retval = read(sfd, buf, sizeof(buf))) < 0) {
                        if (errno == EAGAIN || errno == EINTR)
                                continue;
                        break;
                }
	hci_rec_event(buf);


#if 
	ogf = 0x08;
	ocf = 0x0008;
	opcode=(unsigned short int)((ocf & 0x03ff)|(ogf << 10));;
	le_adv_data.pkt_type=0x01;
	le_adv_data.opcode_lsb = (unsigned char)(opcode >>8);
	le_adv_data.opcode_msb = (unsigned char)(opcode & 0x00ff);
	le_adv_data.plen=32;
	le_adv_data.adv_len = 5;
	strncpy(le_adv_data.adv_data,"MANOJ",5);
	/*Writing to the HCI*/
	retval=write(sfd,&le_adv_data,sizeof(le_adv_data));
	perror("write");
	if(retval <0)
		return 0;
	/*Reading from HCI*/
	while ((retval = read(sfd, buf, sizeof(buf))) < 0) {
                        if (errno == EAGAIN || errno == EINTR)
                                continue;
                        break;
                }

	hci_rec_event(buf);
	
#if 0
	switch(buf[0])/*Type of command*/
	{
	case 0x01:
		printf("COMMAND\n");
		break;
	case 0x04:
		printf("EVENT PACKET\n");
		if(buf[1] == 0x0e)//Command complete
		{
			printf("Length.......0x%02X\n",buf[2]);
			num_cmds = buf[3];
			printf("Number of hci command can execute....0x%02X\n",buf[3]);
			printf("Number of hci command can execute....%d\n",num_cmds);
			printf("OPCODE=0x%02X%02X\n",buf[4],buf[5]);
			printf("Status=0x%02X\n",buf[6]);
		}
		break;
	default :
		printf("Default packet.....0x%02X\n",buf[0]);
		break;
	}
#endif
	// printf("0x%02x   0x%02x   0x%02x   0x%02X   0x%02x    0x%02X\n",buf[0],buf[1],buf[2],buf[3],buf[4],buf[5]);	
	//read(sfd,buf,sizeof(buf));
	//perror("read");
	return 1;
}

int num_cmds = 0;
int hci_rec_event(unsigned char *buf)
{
        switch(buf[0])/*Type of command*/
        {
        case 0x01:
                printf("COMMAND\n");
                break;
        case 0x04:
                printf("EVENT PACKET\n");
                if(buf[1] == 0x0e)//Command complete
                {
                        printf("Length.......0x%02X\n",buf[2]);
                        num_cmds = buf[3];
                        printf("Number of hci command can execute....0x%02X\n",buf[3]);
                        printf("Number of hci command can execute....%d\n",num_cmds);
                        printf("OPCODE=0x%02X%02X\n",buf[4],buf[5]);
                        printf("Status=0x%02X\n",buf[6]);
                }
                break;
        default :
                printf("Default packet.....0x%02X\n",buf[0]);
                break;
        }

}
