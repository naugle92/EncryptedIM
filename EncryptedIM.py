import sys
import socket
import select
import string
import argparse
import hashlib
import binascii
import hmac
import random
from Crypto.Cipher import AES
from Crypto.Hash import HMAC
import base64
import os



HOST = ""
PORT = 1992

SIG_SIZE = hashlib.sha1().digest_size
mode = AES.MODE_CBC

total = len(sys.argv)

#cancel everything if there are not exactly 3 arguments
if (total != 7) and (total != 6):
	print("6 or 7 arguments needed. Should be 'python UnencryptedIM.py -s|-c <name>'")
	sys.exit()

#flag determines if it is a server or client
flag = str(sys.argv[1])

parser = argparse.ArgumentParser(description = 'A P2P IM service.')
parser.add_argument('-c', dest='connect', metavar='HOSTNAME', type=str,
	help = 'Host to connect to')
parser.add_argument('-s', dest='server', action='store_true',
	help = 'Run as server (on port 9999)')
parser.add_argument('-confkey', dest='confkey', metavar='CONFKEY', type=str,
	help = 'Confidentiality key. The key used to hash the messages.')
parser.add_argument('-authkey', dest='authkey', metavar='AUTHKEY', type=str,
	help = 'Authorization key. The key used to verify the identity of the sender')


args = parser.parse_args()

#confkey = args.confkey
#authkey = args.authkey


#hash the keys and take the first 16 bytes (128 bits) so that are the correct length
kOne = (hashlib.sha1(args.confkey).digest())[:16]
kTwo = (hashlib.sha1(args.authkey).digest())[:16]


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
						data = fromClient[:-SIG_SIZE]
						signiture = fromClient[-SIG_SIZE:]

						#If the authkey is wrong, this will return true and close the connection
						if hmac.new(kTwo, data, hashlib.sha1).digest() != signiture:
							print ("Message authentication failed")
							conn.close()
							sys.exit()

						#IV is the first 16 chars of the data string
						iv = data[:16]

						#decrypt ciphertext with AES128 using the key and the IV sent over
						decryptor = AES.new(kOne, mode, iv)
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
						encryptor = AES.new(kOne, mode, iv)
						ciphertext = encryptor.encrypt(toClient)

						#add inegrity by signing the message using HMAC and sha1
						sign = hmac.new(kTwo, iv + ciphertext, hashlib.sha1).digest()

						#send the IV, ciphertext, and signiture in a nice little package 
						conn.send(iv + ciphertext + sign)
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


	while True:
		read, write, err = select.select(possible_sockets, [], [], 1)


		for s in read:
			#if the message is coming from the remote server
			if (s==sock):
				#recieve the message from the server
				fromServer = s.recv(1024)

				if fromServer:
					#data = IV + ciphertext. signiture is the hmac
					data = fromServer[:-SIG_SIZE]
					signiture = fromServer[-SIG_SIZE:]

					#If the authkey is wrong, this will return true and close the connection
					if hmac.new(kTwo, data, hashlib.sha1).digest() != signiture:
						print ("Message authentication failed")
						sock.close()
						sys.exit()

					#IV is the first 16 chars of the data string
					iv = data[:16]

					#decrypt the ciphertext with confkey, IV in AES 128 mode
					decryptor = AES.new(kOne, mode, iv)
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

				#encrypt it with the IV and confkey(kOne)
				encryptor = AES.new(kOne, mode, iv)
				ciphertext = encryptor.encrypt(toServer)
				
				#add inegrity by signing the message using HMAC and sha1
				sign = hmac.new(kTwo, iv + ciphertext, hashlib.sha1).digest()

				#send the whole packet
				sock.send(iv + ciphertext + sign)

		

	sock.close


else:
	print ("Flag is not valid. '-s' or '-c' should be used.")
	sys.exit()