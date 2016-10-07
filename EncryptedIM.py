#####################################################
#				EncryptedIM.py 						#
#####################################################
# Author : Nicolas Naugle							#
# Date   : 7 October 2016							#
# Purpose: This Python program is an encrypted 		#
#			instant messanger. Keys are exchanged	#
#			using Diffie-Hellman and messages are 	#
# 			encrypted using AES-128. 				#
#													#
# Input  : To run this program, two instances will  #
#			need to be created, a server and a 		#
#			client. The server should be started	#
#			first by running 						#
#				python EncryptedIM.py -s 			#
#		   The second instance is the client, and	#
#			you will need the IP or hostname of		#
# 			the server. To run, enter				#
#				python EncryptedIM.py -c <hostIP>	#
#													#
# Note   : This may take a few seconds before the 	#
#			key exchange is completed				#
#													#
# Explanation of the Diffie-Hellman Exchange :      #
#		    In DH, the client and server both have  #
#			hardcoded base (g) and prime (p) values #
#			Server and client both generate random  #
#			numbers that they keep secret (a and b, #
#			respectively). Server and client then  	#
#			compute A and B using					#
#				X  =  g^(x) mod p 					#
#			where X and x are either A and a, or B 	#
#			and b, respectively. Server and client 	#
#			recieves the others shared portion of   #
# 			the key. So the server recieves B from  #
#			the client, who recieves A from the     #
#			server. To compute the shared secret	#
#			key (s), both parties run 				#
#				s  =  Y^(x) mod p  					#
#			where Y is the value recieved from the 	#
#			other party (A or B) and x is the  		#
#			secret value known only to the  		#
#			user (a or b). 							#
#####################################################

import sys
import socket
import select
import string
import argparse
import hashlib
import random
from Crypto.Cipher import AES
import os



HOST = ""
PORT = 9999

SIG_SIZE = hashlib.sha1().digest_size
mode = AES.MODE_CBC


baseG = 2
primeP = 0x00cc81ea8157352a9e9a318aac4e33ffba80fc8da3373fb44895109e4c3ff6cedcc55c02228fccbd551a504feb4346d2aef47053311ceaba95f6c540b967b9409e9f0502e598cfc71327c5a455e2e807bede1e0b7d23fbea054b951ca964eaecae7ba842ba1fc6818c453bf19eb9c5c86e723e69a210d4b72561cab97b3fb3060b


total = len(sys.argv)

#cancel everything if there are not exactly 3 arguments
if (total != 2) and (total != 3):
	print("2 or 3 arguments needed. Should be 'python UnencryptedIM.py -s|-c <host>'")
	sys.exit()

#flag determines if it is a server or client
flag = str(sys.argv[1])

parser = argparse.ArgumentParser(description = 'A P2P IM service.')
parser.add_argument('-c', dest='connect', metavar='HOSTNAME', type=str,
	help = 'Host to connect to')
parser.add_argument('-s', dest='server', action='store_true',
	help = 'Run as server (on port 9999)')


args = parser.parse_args()

#exponentiation by squaring technique
def exponent(g, x):
    r = 1
    while 1:
        if x % 2 == 1:
            r *= g
        x /= 2
        if x == 0:
            break
        g *= g

    return r

#compute the shared and secret parts of the keys
def computeKey(base, aORb):
	AB = exponent(base, int(aORb, 16)) % int(primeP)
	return AB 

#generate a random number for the a and b values in the DH exchange
def generateRandomHex():
	return os.urandom(2).encode('hex')




#server
if (flag == "-s"):

	#create a socket and bind it to the chosen port
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.bind((HOST, PORT))
	
	#only one client
	sock.listen(1)
	#sock.setblocking(0)

	#print ("Server listening on port " + str(PORT) + "...")


	#accepts connection requests from clients
	conn, addr = sock.accept()
	possible_sockets = [sys.stdin, sock, conn]
	#print ("Server is connected to the client and running on port " + str(PORT) + ".")

	#receive B and remove newline from the end since that is not to be included
	B = conn.recv(4096).rstrip('\n')

	#compute and send A
	a = generateRandomHex()
	A = computeKey(baseG, a)
	conn.send(str(A) + '\n')


	#compute secret key using A and B with p and g, then hashing and taking the first 128 bits
	s = computeKey(int(B), a)
	key = (hashlib.sha1(str(s)).digest())[:16]

	while True:
		#figure out reading and writing
		read, write, err = select.select(possible_sockets, [], [], 1)

		try:

			for s in read:
				
				#if there is a new connection
				if s == conn:
					
					#message recieved from the client
					fromClient = s.recv(1024)
					
					#if there is a message, print that bitch out
					if fromClient:
						#data = IV + ciphertext. signiture is the hmac
						data = fromClient

						#IV is the first 16 chars of the data string
						iv = data[:16]

						#decrypt ciphertext with AES128 using the key and the IV sent over
						decryptor = AES.new(key, mode, iv)
						plain = decryptor.decrypt(data[16:])

						#strip any padding added to the message and add a newline so that it prints. Print the message
						plain = plain.rstrip(' ')
						plain += '\n'
						sys.stdout.write(plain)

				#if the message is from stdin, print it and send it
				else:
					try:
						#read the message and strip the newline from it
						toClient = sys.stdin.readline()
						toClient = toClient.rstrip('\n')
						
						#generate a random IV
						iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
						
						#if the message is not divisible by 16, pad whitespace to the end of it
						if len(toClient) == 0:
							break
						elif len(toClient) % 16 != 0:
							toClient += ' ' * (16 - len(toClient) % 16)

						#encrypt using AES128 with the key from the user
						encryptor = AES.new(key, mode, iv)
						ciphertext = encryptor.encrypt(toClient)

						#send the IV, ciphertext, and signiture in a nice little package 
						conn.send(iv + ciphertext)
						#conn.send(iv)

					except:
						print("Connection from client lost")
						conn.close()
						sys.exit()

		except EOFError:
			conn.close()

	#close out of the connection
	conn.close()





#client
elif (flag == "-c"):
	
	#This is the name of the client or server
	hostname = args.connect

	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


	possible_sockets = [sys.stdin, sock]

	#print ("Attempting to connect to " + str(hostname) + " on port " + str(PORT) + ".")

	try:
		#connect to the server
		sock.connect((hostname,PORT))

	except:
		print("Server is not available at this time. (Re)Start the server before trying again.")
		sys.exit()

	#print "Connected to " + str(hostname) + " on port " + str(PORT) + "."

	#compute B and send B
	#b should be a cryptographically random number
	b = generateRandomHex()
	B = computeKey(baseG, b)
	sock.send(str(B) + '\n')

	#receive A and remove newline
	A = sock.recv(4096).rstrip('\n')

	#compute secret key
	s = computeKey(int(A), b)
	key = (hashlib.sha1(str(s)).digest())[:16]

	while True:
		read, write, err = select.select(possible_sockets, [], [], 1)


		for s in read:
			#if the message is coming from the remote server
			if (s==sock):
				#recieve the message from the server
				fromServer = s.recv(1024)

				if fromServer:
					#data = IV + ciphertext. signiture is the hmac
					data = fromServer

					#IV is the first 16 chars of the data string
					iv = data[:16]

					#decrypt the ciphertext with confkey, IV in AES 128 mode
					decryptor = AES.new(key, mode, iv)
					plain = decryptor.decrypt(data[16:])
					
					#strip any whitespace and add a newline. Print the message.
					plain = plain.rstrip(' ')
					plain += '\n'
					sys.stdout.write(plain)

				else:
					print ("Disconnected from the server.")
					sys.exit()
			else:
				#read the input and remove the newline
				toServer = sys.stdin.readline()
				toServer = toServer.rstrip('\n')

				#generate a random IV
				iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
				
				#ensure that the message is divisible by 16, add whitespace if needed
				if len(toServer) == 0:
					break
				elif len(toServer) % 16 != 0:
					toServer += ' ' * (16 - len(toServer) % 16)

				#encrypt it with the IV and confkey(key)
				encryptor = AES.new(key, mode, iv)
				ciphertext = encryptor.encrypt(toServer)
				

				#send the whole packet
				sock.send(iv + ciphertext)

		

	sock.close


else:
	print ("Flag is not valid. '-s' or '-c' should be used.")
	sys.exit()


