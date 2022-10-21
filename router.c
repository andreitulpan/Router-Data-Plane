#include "queue.h"
#include "skel.h"

/* Functia scade TTL-ul si updateaza checksum-ul */
void ttl_checksum_update(struct iphdr *ip_hdr) {

	// new_checksum = old_checksum + old_ttl + ~new_ttl
	unsigned long new_check;
	unsigned short old_ttl, new_ttl;

	old_ttl = ntohs(ip_hdr->ttl);			// old_ttl network -> host
	ip_hdr->ttl --;
	new_ttl = ntohs(ip_hdr->ttl);			// new_ttl network -> host
	new_check = ntohs(ip_hdr->check);		// new_checksum = old_checksum
	new_check += old_ttl;					// new_checksum += old_ttl
	new_check += (~new_ttl & 0xffff);		// new_checksum += !new_ttl
	new_check = (new_check & 0xffff) + (new_check>>16);
	ip_hdr->check = htons(new_check + (new_check>>16));		// sum host -> network
}

/* Functie asemanatoare cu strcmp dar pentru adrese mac */
int compare_mac_address(uint8_t *mac_addr1, uint8_t *mac_addr2) {
	for (int i = 0; i < 6; i++) {
		if (mac_addr1[i] != mac_addr2[i])
			return 1;
	}
	return 0;
}

/* Functia verifica daca pachetul este trimis pentru noi in functie de mac */
int verify_mac_address(packet *m, struct ether_header *eth_hdr) {

	int flag = 1;

	// Aflu mac-ul corespunzator interfetei pe care a venit pachetul
	uint8_t my_mac[ETH_ALEN];
	get_interface_mac(m->interface, my_mac);

	// Initializez o adresa mac de broadcast
	uint8_t broadcast_mac[ETH_ALEN];
	hwaddr_aton("FF:FF:FF:FF:FF:FF", broadcast_mac);

	// Verific daca mac-ul destinatie este acelasi cu cel al interfetei pe
	// care a fost primit sau daca mac-ul de destinatie este de tip broadcast
	if (compare_mac_address(eth_hdr->ether_dhost, broadcast_mac) != 0
		&& compare_mac_address(eth_hdr->ether_dhost, my_mac) != 0) {
		flag = 0;
	}
	return flag;
}

/* Functia ne intoarce cea mai buna ruta din tabela de rutare */
struct route_table_entry *get_best_route(struct route_table_entry *rtable,
										size_t rtable_size, uint32_t dest_ip) {

    size_t idx = -1;

	// Iterez prin tabela de rutare si caut cea mai buna ruta
    for (size_t i = 0; i < rtable_size; i++) {
        if ((ntohl(dest_ip) & ntohl(rtable[i].mask)) == ntohl(rtable[i].prefix)) {
			if (idx == -1) idx = i;
			else if (ntohl(rtable[idx].mask) < ntohl(rtable[i].mask)) idx = i;
		}
    }

    if (idx == -1)
        return NULL;
	else
		return &rtable[idx];
}

/* Functia ne cauta un entry in arp_cache */
int find_in_arp_cache(struct arp_entry *arp_cache, size_t cache_size, uint32_t dest_ip, uint8_t *dest_host) {

	// Iterez prin tot cache-ul si daca gasesc ip-ul returnez 1 si trimit mac-ul prin referinta
	for (int i = 0; i < cache_size; i++) {
		if (arp_cache[i].ip == dest_ip) {
			memcpy(dest_host, (arp_cache[i].mac), 6);
			return 1;
		}
	}
	return 0;
}

/* Functia trimite un pachet ICMP, iar tipul acestuia este ales prin variabila type */
void icmp_send(packet *m, struct iphdr *ip_hdr,struct ether_header *eth_hdr,
												uint8_t *my_mac, int type) {

	// Initializez un ICMP header
	struct icmphdr icmp_hdr;
	icmp_hdr.code = 0;
	icmp_hdr.type = type;
	icmp_hdr.checksum = 0;
	memcpy(m->payload + sizeof(struct ether_header) + sizeof(struct iphdr) + 64, m->payload + sizeof(struct ether_header) + sizeof(struct iphdr), 64);
	memcpy(m->payload + sizeof(struct ether_header) + sizeof(struct iphdr), &icmp_hdr, sizeof(struct icmphdr));
	icmp_hdr.checksum = icmp_checksum((uint16_t *)(m->payload + sizeof(struct ether_header) + sizeof(struct iphdr)), (sizeof(struct icmphdr) + 64));

	// Updatez header-ul IP
	ip_hdr->protocol = 1;
	ip_hdr->ttl = 64;
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr->daddr = ip_hdr->saddr;
	struct in_addr my_ip;
	inet_aton(get_interface_ip(m->interface), &my_ip);
	ip_hdr->saddr = my_ip.s_addr;
	ip_hdr->check = htons(0);
	ip_hdr->check = ip_checksum((uint8_t *)ip_hdr, sizeof(struct iphdr));

	// Updatez header-ul Ethernet
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr->ether_shost, my_mac, 6);


	// Updatez lungimea pachetului
	m->len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + 64;

	// Trimit pachetul
	send_packet(m);
}

/* Functia trimite un ICMP reply*/
void icmp_reply(packet *m, struct icmphdr *icmp_hdr, struct ether_header *eth_hdr, struct iphdr *ip_hdr, uint8_t *my_mac) {

	// Modific header-ul ICMP
	icmp_hdr->type = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = icmp_checksum((uint16_t *)(m->payload + sizeof(struct ether_header) + sizeof(struct iphdr)), (sizeof(struct icmphdr) + 64));

	// Aflu ip-ul routerului de pe interfata curenta
	struct in_addr my_ip;
	inet_aton(get_interface_ip(m->interface), &my_ip);

	// Updatez header-ul IP
	ip_hdr->ttl = 64;
	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = my_ip.s_addr;
	ip_hdr->check = htons(0);
	ip_hdr->check = ip_checksum((uint8_t *)ip_hdr, sizeof(struct iphdr));

	// Updatez header-ul Ethernet
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr->ether_shost, my_mac, 6);


	// Trimit pachetul
	send_packet(m);
}

/* Functia se ocupa cu trimiterea unui ARP request*/
void send_arp_request(uint8_t *shost, uint32_t ip_s, uint8_t *dhost,
										uint32_t ip_d, int interface) {

	// Creez un pachet nou
	packet m;
	m.interface = interface;

	// Initializez un Ethernet header pentru noul pachet
	struct ether_header eth_hdr;
	memcpy(eth_hdr.ether_dhost, dhost, 6);
	memcpy(eth_hdr.ether_shost, shost, 6);
	eth_hdr.ether_type = htons(ETHERTYPE_ARP);

	// Initializez un ARP header pentru noul pachet
	struct arp_header arp_hdr;
	arp_hdr.op = htons(1); 		// 1 = request
	arp_hdr.htype = htons(1); 	// 1 = MAC
	arp_hdr.hlen = 6;
	arp_hdr.ptype = htons(ETHERTYPE_IP); 	// ETHERTYPE_IP = 0x0800
	arp_hdr.plen = 4;
	memcpy(arp_hdr.sha, shost, 6);	// adresa mac a interfetei routerului
	// arp_hdr.tha // adresa mac necunoscuta
	arp_hdr.spa = ip_s;
	arp_hdr.tpa = ip_d;

	// Asamablez payload-ul
	memcpy(m.payload, &eth_hdr, sizeof(struct ether_header));
	memcpy((m.payload + sizeof(struct ether_header)), &arp_hdr, sizeof(struct arp_header));

	m.len = sizeof(struct ether_header) + sizeof(struct arp_header);

	// Trimit pachetul pentru ARP request
	send_packet(&m);

}

/* Functia trimite un ARP Reply */
void send_arp_reply(packet *m, struct ether_header *eth_hdr, struct arp_header *arp_hdr) {

	// Aflu mac-ul corespunzator interfetei pe care a venit pachetul
	uint8_t my_mac[ETH_ALEN];
	get_interface_mac(m->interface, my_mac);

	// Ii fac update header-ului ARP pentru a trimite reply-ul
	uint32_t tmp_addr;		// Adresa ip temporara
	arp_hdr->op = htons(2); 	// op = Reply code
	memcpy(arp_hdr->tha, arp_hdr->sha, 6); 		// Setez adresa mac de destinatie cu cea a sursei
	memcpy(arp_hdr->sha, my_mac, 6);	// Setez adresa mac a sursei cu adresa mac a routerului
	tmp_addr = arp_hdr->tpa; 	// Salvez adresa ip a routerului de pe aceasta interfata
	arp_hdr->tpa = arp_hdr->spa;	// Setez adresa ip a tintei cu cea a sursei
	arp_hdr->spa = tmp_addr; 	// Setez adresa ip a sursei cu adresa ip a routerului

	// Ii fac update header-ului Ethernet pentru a trimite reply-ul
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr->ether_shost, my_mac, 6);

	// Trimit pachetul
	send_packet(m);
}

/* Functia primeste un ARP reply si salveaza datele in cache */
void receive_arp_reply(struct arp_header *arp_hdr, struct arp_entry *arp_cache,
														size_t *arp_cache_size) {

	// Initializez o structura arp_entry pentru cache
	struct arp_entry arp_entry;
	arp_entry.ip = arp_hdr->spa;
	memcpy(arp_entry.mac, arp_hdr->sha, 6);

	// Adaug arp_entry-ul in cache
	arp_cache[*arp_cache_size] = arp_entry;
	(*arp_cache_size)++;
}

/* Functia trimite pachetel din coada daca s-a primit un ARP reply pentru ele */
void send_packet_from_queue(queue q1, queue q2, queue queue_sel, struct route_table_entry *rtable,
							size_t rtable_size, struct arp_header *arp_hdr, int *queue_in_use) {

	// Parcurg coada de pachete si trimit pachetele corespunzatoare
	packet *msg;
	while (!queue_empty(queue_sel)) {
		// Scot primul pachet din coada
		msg = (packet *)queue_deq(queue_sel);
		// Extrag header-ul IP din pachet
		struct iphdr *ip_hdr_msg;
		ip_hdr_msg = (struct iphdr *)(msg->payload + sizeof(struct ether_header));

		// Gasesc next hop-ul pentru a verifica daca trimit pachetul
		struct route_table_entry *best_route;
		best_route = get_best_route(rtable, rtable_size, ip_hdr_msg->daddr);
		if (best_route->next_hop == arp_hdr->spa) {

			// Adaug mac-ul destinatie in Ethernet header
			struct ether_header *eth_hdr_msg;
			eth_hdr_msg = (struct ether_header*)(msg->payload);
			memcpy(eth_hdr_msg->ether_dhost, arp_hdr->sha, 6);
			// Trimit pachetul
			send_packet(msg);
		} else {
			if (*queue_in_use) {
				queue_enq(q2, (void *)msg);
			} else {
				queue_enq(q1, (void *)msg);
			}
		}
		if (!queue_empty(queue_sel)) {
			*queue_in_use = !(*queue_in_use);
		}
	}
}

/* Functia se ocupa de redirectarea pachetelor IPv4 catre destinatie */
void forward_ipv4(packet *m, struct ether_header *eth_hdr, struct route_table_entry *rtable,
	size_t rtable_size, struct arp_entry *arp_cache, size_t *arp_cache_size, queue queue_sel) {

	// Aflu mac-ul corespunzator interfetei pe care a venit pachetul
	uint8_t my_mac[ETH_ALEN];
	get_interface_mac(m->interface, my_mac);

	// Initializez o adresa mac de broadcast
	uint8_t broadcast_mac[ETH_ALEN];
	hwaddr_aton("FF:FF:FF:FF:FF:FF", broadcast_mac);

	// Extrag header-ul IP
	struct iphdr *ip_hdr;
	ip_hdr = (struct iphdr *)(m->payload + sizeof(struct ether_header));

	// Aflu ip-ul routerului de pe interfata curenta
	struct in_addr my_ip;
	inet_aton(get_interface_ip(m->interface), &my_ip);

	// ICMP request -> ICMP reply
	struct icmphdr *icmp_hdr = (struct icmphdr *)(m->payload + sizeof(struct ether_header) + sizeof(struct iphdr));
	if (ip_hdr->daddr == my_ip.s_addr && icmp_hdr->type == 8) {
		icmp_reply(m, icmp_hdr, eth_hdr, ip_hdr, my_mac);
		return;
	}


	// Verific daca checksum-ul calculat este egal cu cel din header
	uint16_t checksum = ip_hdr->check;
	ip_hdr->check = htons(0);
	uint16_t checksum2 = ip_checksum((uint8_t *)ip_hdr, sizeof(struct iphdr));
	if (checksum2 != checksum) {
		return;
	}

	ip_hdr->check = checksum;

	// Verific TTL-ul daca este diferit de 1 sau 0
	if (ip_hdr->ttl == 1 || ip_hdr->ttl == 0) {
		// Trimitere mesaj ICMP de tip "Time exceeded"
		icmp_send(m, ip_hdr, eth_hdr, my_mac, 11);
		return;
	}

	// Gasesc next hop-ul tabela de rutare
	struct route_table_entry *best_route;
	best_route = get_best_route(rtable, rtable_size, ip_hdr->daddr);

	// Verific daca s-a gasit o intrare a ip-ul de destinatie in rtable
	if (best_route == NULL) {
		// Trimit mesaj ICMP de tip "Destination unreacheable"
		icmp_send(m, ip_hdr, eth_hdr, my_mac, 3);
		return;
	}

	// Updatez mac-ul cu cel al interfetei actuale
	get_interface_mac(best_route->interface, my_mac);

	// Aflu adresa ip de pe interfata actuala
	struct in_addr dest_ip;
	inet_aton(get_interface_ip(best_route->interface), &dest_ip);

	// Updatez interfata
	m->interface = best_route->interface;

	// Scad TTL-ul cu 1 si updatez checksum-ul
	ttl_checksum_update(ip_hdr);

	// Rescriu adresele de Layer 2
	memcpy(eth_hdr->ether_shost, my_mac, 6);
	uint8_t dhost[ETH_ALEN];
	if (find_in_arp_cache(arp_cache, *arp_cache_size, best_route->next_hop, dhost) == 1) {
		memcpy(eth_hdr->ether_dhost, dhost, 6);

		// Trimit pachetul
		send_packet(m);

	} else {

		// Trimit un ARP request si pun pachetul in coada
		send_arp_request(my_mac, dest_ip.s_addr, broadcast_mac, best_route->next_hop, best_route->interface);

		packet *msg = malloc(sizeof(packet));
		memcpy(msg, m, sizeof(packet));
		queue_enq(queue_sel, (void *)msg);
	}
}

int main(int argc, char *argv[]) {

	packet m;
	int rc;

	// Do not modify this line
	init(argc - 2, argv + 2);

	// Initializare tabela de rutare
	struct route_table_entry *rtable;
	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	size_t rtable_size = read_rtable(argv[1], rtable);

	// Initializare ARP cache
	struct arp_entry *arp_cache;
	arp_cache = malloc(sizeof(struct arp_entry) * 50);
	size_t arp_cache_size = 0;

	// Initializare cozi de pachete
	int queue_in_use = 1;
	queue q1 = queue_create();
	queue q2 = queue_create();
	queue queue_sel;

	while (1) {

		// Primesc un pachet
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");

		// Extrag header-ul Ethernet
		struct ether_header *eth_hdr = (struct ether_header*)(m.payload);

		// Verific daca mac-ul destinatie este acelasi cu cel al interfetei pe
		// care a fost primit sau daca mac-ul de destinatie este de tip broadcast
		if (!verify_mac_address(&m, eth_hdr))
			continue;

		// Updatez coada curenta
		if (queue_in_use)
			queue_sel = q1;
		else
			queue_sel = q2;

		// Verific daca tipul pachetului este ARP
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {

			// Extrag header-ul ARP
			struct arp_header *arp_hdr;
			arp_hdr = (struct arp_header *)(m.payload + sizeof(struct ether_header));

			// Verific daca am primit un ARP request
			if (arp_hdr->op == htons(1)) {
				send_arp_reply(&m, eth_hdr, arp_hdr);
			// Verific daca am primit un ARP reply
			} else if (arp_hdr->op == htons(2)) {
				receive_arp_reply(arp_hdr, arp_cache, &arp_cache_size);
				send_packet_from_queue(q1, q2, queue_sel, rtable, rtable_size, arp_hdr, &queue_in_use);
			}

		// Verific daca tipul pachetului este IPv4
		} else if (ntohs(eth_hdr->ether_type) == 0x0800) {
			forward_ipv4(&m, eth_hdr, rtable, rtable_size, arp_cache, &arp_cache_size, queue_sel);
		}
	}

	// Eliberez memoria alocata dinamic
	free(rtable);
	free(arp_cache);
}
