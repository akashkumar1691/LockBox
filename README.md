# LockBox
An End-To-End encrypted file sharing system similar to Google Docs or Dropbox, but with secured with cryptography such that the server cannot view or tamper with the data

## Features
This program allows users to create accounts and create sharable text documents. These documents can be edited by anyone who it is shared with. Those who the document is share with can share with others, and the owner can always unshare with anybody they choose. 

## Security Features
We assume the server, known as the DataStore, is malicious such that any information stored in the datastore is not able to be read or tampered with without detection. Furthermore, since the datastore is accesible to users, we cryptographically secured the documents such that when a document is unshared with an individual, they are also assumed to be malicious and are not able to surmise anything about future edits to the document.

## Using the Program
All available methods, along with descriptions can be found in [`client/client.go`](client/client.go).

Examples on how to use these methods in a manner simulating the users and adversaries can be found in [`client_test/client_test.go`](client_test/client_test.go).

