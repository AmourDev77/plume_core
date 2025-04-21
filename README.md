This are the core functions of plume apps.  
Please run `cargo doc --open` to see the full documentation


# Add friend process 
this process is in construction, for now the only way to add a friend is to get his public x25519 and public ED25519 keys
1. Client1 generates keys
2. Store transaction so that target can respond anytime
3. Send the public key to client2 along with usual data (username)
4. If the client2 decline, send a deny response and client1 delete transaction
5. Client2 also generates keys, and generate a shared key from all the data received
6. Client2 send back public key
7. Clietn1 generate shared keys
