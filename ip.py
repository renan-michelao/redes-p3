import struct
from iputils import *


class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.tabela = []

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
            self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        dest, = struct.unpack('!I', str2addr(dest_addr))
        # A tabela está ordenada do prefixo mais longo para o mais curto, então
        # a primeira entrada que casar é a de prefixo mais longo
        for rede, mascara, next_hop in self.tabela:
            if dest & mascara == rede:
                return next_hop
        return None

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        self.tabela = []
        for cidr, next_hop in tabela:
            endereco, n = cidr.split('/')
            n = int(n)
            mascara = (0xffffffff << (32 - n)) & 0xffffffff
            rede, = struct.unpack('!I', str2addr(endereco))
            self.tabela.append((rede & mascara, mascara, next_hop))
        # Ordena do prefixo mais longo para o mais curto
        self.tabela.sort(key=lambda entrada: entrada[1], reverse=True)

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # Cabeçalho IPv4 sem opções: versão 4, IHL 5 (20 bytes), TTL 64, protocolo TCP
        cabecalho = struct.pack('!BBHHHBBH', (4 << 4) | 5, 0, 20 + len(segmento),
                                0, 0, 64, IPPROTO_TCP, 0) + \
            str2addr(self.meu_endereco) + str2addr(dest_addr)
        checksum = calc_checksum(cabecalho)
        cabecalho = cabecalho[:10] + struct.pack('!H', checksum) + cabecalho[12:]
        datagrama = cabecalho + segmento
        self.enlace.enviar(datagrama, next_hop)
