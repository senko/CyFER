#!/usr/bin/env python

import sys
import cyfer.hash, cyfer.blockcipher, cyfer.streamcipher, cyfer.pk, cyfer.keyex

def test_hash():
	text = "Hello World"
	ctx = cyfer.hash.Hash("MD5")
	ctx.Update(text)
	res = ctx.Finish()
	res = "".join(map(lambda x: "%02x" % ord(x), res))
	return res == "b10a8db164e0754105b7a99be72e3fe5"

def test_bcipher():
	plaintext = "01234567"
	ctx = cyfer.blockcipher.BlockCipher("Blowfish", "Forty-two", "ECB", None)
	ciphertext = ctx.Encrypt(plaintext)
	result = ctx.Decrypt(ciphertext)
	return plaintext == result

def test_scipher():
	plaintext = "A quick brown fox jumps over the lazy dog."
	enc = cyfer.streamcipher.StreamCipher("RC4", "Forty-two")
	dec = cyfer.streamcipher.StreamCipher("RC4", "Forty-two")
	ciphertext = enc.Encrypt(plaintext)
	result = dec.Decrypt(ciphertext)
	return plaintext == result

def test_pk():
	plaintext = "A quick brown fox jumps over the lazy dog."
	ctx = cyfer.pk.Pk("RSA")
	ctx.GenerateKey(1024)
	keys = ctx.ExportKey()

	ctx = cyfer.pk.Pk("RSA")
	ctx.ImportKey(None, keys[1])
	ciphertext = ctx.Encrypt(plaintext)

	ctx = cyfer.pk.Pk("RSA")
	ctx.ImportKey(keys[0], None)
	result = ctx.Decrypt(ciphertext)

	return plaintext == result[:len(plaintext)]

def test_keyex():
	alice = cyfer.keyex.KeyEx("DH")
	alice.GenerateKey()
	a = alice.PublicKey()

	bob = cyfer.keyex.KeyEx("DH")
	bob.GenerateKey()
	b = bob.PublicKey()

	alice.ComputeKey(b)
	bob.ComputeKey(a)

	return alice.SharedKey(100) == bob.SharedKey(100)
	

def perform_test(code, subject):	
	print "Testing" , subject , "..",
	if code():
		print "passed"
	else:
		print "failed"
		sys.exit(1)


perform_test(test_hash, "hash")
perform_test(test_bcipher, "block cipher")
perform_test(test_scipher, "stream cipher")
perform_test(test_pk, "public-key algorithm")
perform_test(test_keyex, "key-exchange algorithm")

sys.exit(0)

# EOF

