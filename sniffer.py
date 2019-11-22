from scapy.all import *

print("########## UDP Sniffer ##########\n")

print("### Configuracion de entrada. ###\n")
ip = input('IP de entrada: ')
port = input('Puerto de entrada: ')
# i = input('Interface de entrada: ')
print("\n#### Configuracion de salida ####\n")
ipout =input('IP de salida: ')
portout = input('Puerto de salida: ')
# iout = input('Interface de salida: ')
print("\n### Escuchando el puerto "+port+" ###")
print("\n### Reenviando al puerto "+portout+" ###\n")

def myFunction(pkt):
	if Raw in pkt:
		send((IP(dst=ipout,src=ip)/UDP(dport=int(portout))/pkt[Raw].load))
		print(pkt[Raw].load)
	else:
		print(pkt)
packets = sniff(filter='udp and port '+port, prn=myFunction)
