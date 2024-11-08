#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>

// Fonction de callback appelée pour chaque paquet capturé
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));

    // Affiche l'adresse source et l'adresse de destination IP
    printf("Paquet capturé:\n");
    printf("Source IP: %s\n", inet_ntoa(ip_hdr->ip_src));
    printf("Destination IP: %s\n", inet_ntoa(ip_hdr->ip_dst));
    printf("Longueur du paquet: %d octets\n\n", pkthdr->len);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Ouvre l'interface pour la capture
    char *dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Erreur en trouvant l'interface : %s\n", errbuf);
        return 1;
    }

    // Ouvre l'interface en mode promiscuous
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Erreur d'ouverture de l'interface %s : %s\n", dev, errbuf);
        return 1;
    }

    // Capture les paquets (NULL signifie aucun filtre)
    if (pcap_loop(handle, 10, packet_handler, NULL) < 0) {
        fprintf(stderr, "Erreur dans la boucle de capture : %s\n", pcap_geterr(handle));
        return 1;
    }

    // Ferme la session de capture
    pcap_close(handle);
    return 0;
}
