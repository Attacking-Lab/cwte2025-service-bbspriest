from confessions import *
from crypto import pubkey, priv, encrypt, decrypt
from datetime import datetime

import socketserver

class ThreadedTCPRequestHandler(socketserver.StreamRequestHandler):
	def die(self):
		self.connection.close()

	def getNumber(self) -> int:
		self.wfile.write(rb'> ')
		value = self.rfile.readline().strip()
		if not value.isdigit():
			self.wfile.write(rb'Begone, foul demon')
			self.die()
			raise Exception('mvm')

		return int(value)

	def getString(self) -> bytes:
		self.wfile.write(rb'> ')

		return self.rfile.readline().strip()
	
	def promptNumber(self, text: bytes):
		self.wfile.write(text)
		return self.getNumber()

	def promptString(self, text: bytes):
		self.wfile.write(text)
		return self.getNumber()

	def confessSin(self):
		self.wfile.write(b'Confess your sins\n')
		frequentSins = [
			'I flagshared in an A/D',
			'I upload a RSA chall prime to factordb',
			'I leaked flags in the discord',
			'I don\'t know what mvm means',
			'I abused university clusters to brute',
			'Confess custom sin'
		]
		pick = self.promptNumber(b'Frequently Confessed Sins:\n' + b''.join([f'({idx}) {sin}\n'.encode() for idx, sin in enumerate(frequentSins)]))

		if pick < len(frequentSins) - 1:
			confessionStr = frequentSins[pick].encode()
		else:
			confessionStr = self.getString()

		confession = Confession(confessionStr)
		sinId = confession.sinId
		absolutionSignature = confession.putConfession()
		
		self.wfile.write(b'You have been absolved of this particular sin.\n')
		self.wfile.write(f'Sin id: {sinId.decode()}.\n'.encode())
		self.wfile.write(f'Absolution signature: {absolutionSignature}.\n'.encode())

	def confessUnforgivableSin(self):
		self.wfile.write(b'Confess your unforgivable sins\n')
		frequentSins = [
			'I put pineapple on pizza',
			'I am speedrunnning the CTF iceberg meme',
			'Confess custom sin'
		]
		pick = self.promptNumber(b'Frequently Confessed Sins:\n' + b''.join([f'({idx}) {sin}\n'.encode() for idx, sin in enumerate(frequentSins)]))

		if pick < len(frequentSins) - 1:
			confessionStr = frequentSins[pick].encode()
		else:
			confessionStr = self.getString()

		ct = encrypt(confessionStr)
		confession = Confession(ct, True)
		sinId = confession.sinId
		decryptionKey = confession.putUnforgivableConfession()
		
		self.wfile.write(b'Yeah no I can\'t forgive this sin\n-Gaspare.\n')
		self.wfile.write(f'Sin id: {sinId.decode()}.\n'.encode())
		self.wfile.write(f'Decryption key: {decryptionKey}.\n'.encode())

	def lookupSins(self):
		self.wfile.write(b'Check if you have been absolved of a particular sin.\n')
		self.wfile.write(b'Enter sin id\n')
		sinId = self.getString()
		self.wfile.write(f'Enter absolution signature\n'.encode())
		absolutionSignature = tuple(map(int, self.getString()[1:-1].split(b', ')))
		try:
			confession = Confession.getConfession(sinId)
		except:
			self.wfile.write(b'This is not a recognized sin. Please confess.\n')
			return

		if not confession.checkConfession(pubkey, absolutionSignature):
			self.wfile.write(b'Invalid absolution signature. This incident will be reported.\n')
			return

		content = confession.content
		self.wfile.write(f'The sin "{content.decode()}" has already been absolved.\n'.encode())

	def lookupUnforgiveableSins(self):
		self.wfile.write(b'Check if you have already confessed an unforgivable sin.\n')
		self.wfile.write(b'Enter sin id\n')
		sinId = self.getString()
		try:
			confession = Confession.getConfession(sinId)
			self.wfile.write(f'Found confession {confession.content.hex()}\n'.encode())
		except:
			self.wfile.write(b'This is not a recognized sin. Please confess.\n')
			return

		self.wfile.write(f'Enter decryption key\n'.encode())
		decryptionKey = self.getNumber()
		decryptedConfession = confession.decryptConfession(decryptionKey)
		if decryptedConfession is None:
			self.wfile.write(b'Invalid decryption key. This incident will be reported.\n')
			return

		self.wfile.write(f'The sin "{decryptedConfession.decode()}" has already been logged.\n'.encode())
	
	def secretFifthOption(self):
		self.wfile.write(b'Check if you have been absolved of a particular sin.\n')
		self.wfile.write(b'Enter generator.\n')
		G = Point(*map(int, self.getString().decode().split(', ')))
		pubkey = G.mul(priv)
		self.wfile.write(f'Your private key {pubkey}.\n'.encode())
		self.wfile.write(b'Enter sin id.\n')
		sinId = self.getString()
		self.wfile.write(f'Enter absolution signature.\n'.encode())
		absolutionSignature = tuple(map(int, self.getString()[1:-1].split(b', ')))
		try:
			confession = Confession.getConfession(sinId)
		except:
			self.wfile.write(b'This is not a recognized sin. Please confess.\n')
			return

		if not confession.checkConfession(pubkey, absolutionSignature):
			self.wfile.write(b'Invalid absolution signature. This incident will be reported.\n')
			return

		content = confession.content
		self.wfile.write(f'The sin "{content.decode()}" has already been absolved.\n'.encode())

	def handle(self):
		self.wfile.write(rb"""
/$$$$$$$  /$$$$$$$   /$$$$$$         
| $$__  $$| $$__  $$ /$$__  $$        
| $$  \ $$| $$  \ $$| $$  \__/        
| $$$$$$$ | $$$$$$$ |  $$$$$$         
| $$__  $$| $$__  $$ \____  $$        
| $$  \ $$| $$  \ $$ /$$  \ $$        
| $$$$$$$/| $$$$$$$/|  $$$$$$/        
|_______/ |_______/  \______/         
                                      
  /$$$$$$  /$$$$$$ /$$   /$$  /$$$$$$ 
 /$$__  $$|_  $$_/| $$$ | $$ /$$__  $$
| $$  \__/  | $$  | $$$$| $$| $$  \__/
|  $$$$$$   | $$  | $$ $$ $$|  $$$$$$ 
 \____  $$  | $$  | $$  $$$$ \____  $$
 /$$  \ $$  | $$  | $$\  $$$ /$$  \ $$
|  $$$$$$/ /$$$$$$| $$ \  $$|  $$$$$$/
 \______/ |______/|__/  \__/ \______/ 
 """ + f"""
Current uptime is {(datetime.now() - starttime).seconds}s
Gaspare's public key: {pubkey}

""".encode())
		while True:
			pick = self.promptNumber(rb"""Father Gaspare is now taking calls
555-123(0) - Confess sin
555-123(1) - Confess unforgivable sin
555-123(2) - Lookup sins
555-123(3) - Lookup unforgivable sins
555-123(4) - Quit
""")
			if pick == 0:
				self.confessSin()
			elif pick == 1:
				self.confessUnforgivableSin() 
			elif pick == 2:
				self.lookupSins()
			elif pick == 3:
				self.lookupUnforgiveableSins()
			elif pick == 5:
				self.secretFifthOption()
			else:
				return


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
	allow_reuse_address = True

if __name__ == '__main__':
	HOST, PORT = '0.0.0.0', 9999
	starttime = datetime.now()

	with ThreadedTCPServer((HOST, PORT), ThreadedTCPRequestHandler) as server:
		print(f'Server listening on {HOST}:{PORT}')
		server.serve_forever()
