# Blocace Javascript Client
The official Javascript client to access Blocace server.

## Blocace web API reference
`static create(protocol, hostname, port)` - Generate random Blocace client key pair and initialize the client class

Example:
```
var blocace = Blocace.create('http', 'localhost', '6899')
```
`static createFromPrivateKey(privKey, protocol, hostname, port)` - Use an existing client private key and initialize the client class

Example:
```
var blocace = Blocace.createFromPrivateKey('81244df62f43a163a2f4a4894ef531ba1a493b921fb3bbaabdb2222e632f7734)
```

`encryptPrivateKey(password)` - Get the encrypted private key. The return value is a concatenation of the salt, IV and the cipher text of the private key

Example:
```
var encryptPrivKey = blocace.encryptPrivateKey('123456')
```

`static decryptPrivateKey(encrypted, password)` - Decrypt the private key from the encryption string, which is a concatenation of the salt, IV and the cipher text of the private key

Example:
```
var decryptPrivKey = Blocace.decryptPrivateKey(encryptPrivKey, '123456')
```

`static verifySignature(rawDocument, signature, address)` - Verify if the signature of a document matches the claimed address (aka. public key). This API can be used to verify the integrity of a document

Example:
```
var isValidSignature = Blocace.verifySignature(queryRes.hits[0]._source, queryRes.hits[0]._signature, blocaceUser.wallet.address)
```

`getPublicKey()` - Get public key of the wallet

Example:
```
var publicKey = blocace.getPublicKey()
```

`async createAccount(accountPayload)` - Create a new account

Example:
```
const accountPayload = {
  'dateOfBirth': '2018-10-01',
  'firstName': 'Hooper',
  'lastName': 'Vincent',
  'company': 'MITROC',
  'position': 'VP of Marketing',
  'email': 'hoopervincent@mitroc.com',
  'phone': '+1 (849) 503-2756',
  'address': '699 Canton Court, Mulino, South Dakota, 9647',
  'publicKey': 'b0a303c71d99ad217c77af1e4d5b85e3ccc3e359d2ac9ff95e042fb0e0016e4d4c25482ba57de472c44c58f6fb124a0ab86613b0dcd1253a23d5ae00180854fa'
}

const accountRes = await Blocace.createAccount(accountPayload, 'http', 'localhost', '6899')
```

`async updateAccount(accountPayload, address)` - Update the account

Example:
```
const accountPayload = {
  'dateOfBirth': '2018-10-01',
  'firstName': 'Hooper',
  'lastName': 'Vincent',
  'company': 'MITROC',
  'position': 'VP of Marketing',
  'email': 'hoopervincent@mitroc.com',
  'phone': '+1 (849) 503-2756',
  'address': '699 Canton Court, Mulino, South Dakota, 9647',
  'publicKey': 'b0a303c71d99ad217c77af1e4d5b85e3ccc3e359d2ac9ff95e042fb0e0016e4d4c25482ba57de472c44c58f6fb124a0ab86613b0dcd1253a23d5ae00180854fa'
}

accountPayload.email = 'asd@asd.com'
const accountUpdateRes = await blocaceUser.updateAccount(accountPayload, accountRes.data.address)
```
Output:
```
{"address":"699 Canton Court, Mulino, South Dakota, 9647","collectionsReadOverride":null,"collectionsWrite":null,"company":"MITROC","dateOfBirth":"2018-10-01","email":"hoopervincent@mitroc.com","firstName":"Hooper","lastName":"Vincent","phone":"+1 (849) 503-2756","position":"VP of Marketing","publicKey":"04b0a303c71d99ad217c77af1e4d5b85e3ccc3e359d2ac9ff95e042fb0e0016e4d4c25482ba57de472c44c58f6fb124a0ab86613b0dcd1253a23d5ae00180854fa","roleName":"user"}
```
`async setAccountReadWrite(permissionPayload, address)` - Grand collection level read/write permission

Example:
```
const accountPermissionRes = await blocace.setAccountReadWrite(permission, accountRes.data.address)
```
Output:
```
{"message":"account permission updated","address":"0xf55486314B0C4F032d603B636327ed5c82218688"}
```
`async getChallenge()` - A challenge issued from Blocace server for the client to authenticate

Example:
```
const challengeResponse = await this.getChallenge()
```
`async getJWT()` - Get the challenge, give back the solution and obtain the JWT ([JSON Web Token](https://jwt.io/))

Example:
```
const jwt = await blocace.getJWT()
```
Output:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlTmFtZSI6ImFkbWluIiwiYWRkcmVzcyI6IjB4RDE2MjFGNzZiMzMzOWIyRUFENTA2ODU5ZGRFRWRhRkZBMWYxOGM1MiIsImF1ZCI6ImJsb2NhY2UgdXNlciIsImV4cCI6MTU4MDM2MTAyOCwiaWF0IjoxNTgwMzYwNDI4LCJpc3MiOiJibG9jYWNlIn0.rKqkdaD-k8HmUW-z0W9WI41SUs7_sqSFdjGePdrYtKQ
```
`async getAccount(address)` - Get the account's information

Example:
```
const account = await blocace.getAccount(accountRes.data.address)
```
Output:
```
{
	"address": "699 Canton Court, Mulino, South Dakota, 9647",
	"collectionsReadOverride": null,
	"collectionsWrite": null,
	"company": "MITROC",
	"dateOfBirth": "2018-10-01",
	"email": "hoopervincent@mitroc.com",
	"firstName": "Hooper",
	"lastName": "Vincent",
	"phone": "+1 (849) 503-2756",
	"position": "VP of Marketing",
	"publicKey": "04b0a303c71d99ad217c77af1e4d5b85e3ccc3e359d2ac9ff95e042fb0e0016e4d4c25482ba57de472c44c58f6fb124a0ab86613b0dcd1253a23d5ae00180854fa",
	"roleName": "user"
}
```
`async createCollection(collectionPayload)` - Create an new collection with schema

Example:
```
const collectionCreationRes = await blocace.createCollection(collectionMappingPaylod)
```
Output:
```
{"message":"collection new1 created"}
```
`async signAndPutDocument(document, collection)` - Write and digitally sign a JSON document to add to a collection

Example:
```
const document = {
  'id': '5bf1d3fdf6fd4a5c4638f64e',
  'guid': 'f51b68c5-f274-4ce1-984f-b4fb4d618ff3',
  'isActive': false,
  'age': 28,
  'name': 'Carly Compton',
  'gender': 'male',
  'registered': '2015-09-18T12:59:51Z',
  'location': {
    'lon': 46.564666,
    'lat': 53.15213
  },
  'tags': [
    'incididunt',
    'dolore'
  ],
  'friends': [
    {
      'id': 0,
      'name': 'Jimenez Byers'
    },
    {
      'id': 1,
      'name': 'Gabriela Mayer'
    }
  ],
  'notExist': 'haha'
}

const putDocRes = await blocaceUser.signAndPutDocument(document, 'new1')
```
Output:
```
{"status":"ok","fieldErrors":null,"isValidSignature":true,"transactionID":"8a545086ebfac8d7f38c08ceb618f2afe35850e9ba9890784abe89288f42e7bd"}
```
`async putDocumentBulk(documents, collection)` - Write a bulk of JSON documents in a single HTTP request to a collection. WARNING: this makes the documents unverifiable

Example:
```
const payload = [
  {...},
  {...},
  {...}
]
await blocaceUser.putDocumentBulk(payload, 'new2')
```

`async query(queryPayload, collection)` - Query the documents from Blocase with a query against a collection. Check out [Blevesearch Query](https://blevesearch.com/docs/Query/) for the query DSL.

Example:
```
const queryPayload = {
  'size': 3,
  'from': 0,
  'query': {
    'match': 'Compton',
    'field': 'name'
  }
}
const queryRes = await blocaceUser.query(queryPayload, 'new1')
```
Output:
```
{
	"collection": "new1",
	"status": {
		"total": 1,
		"failed": 0,
		"successful": 1
	},
	"total_hits": 10,
	"hits": [{
		"_id": "8a545086ebfac8d7f38c08ceb618f2afe35850e9ba9890784abe89288f42e7bd",
		"_blockId": "cfc01dc667753185a5635b33ebbff42b452476f15a4f63fceb210aad68dac3b8",
		"_source": "{\"id\":\"5bf1d3fdf6fd4a5c4638f64e\",\"guid\":\"f51b68c5-f274-4ce1-984f-b4fb4d618ff3\",\"isActive\":false,\"age\":28,\"name\":\"Carly Compton\",\"gender\":\"male\",\"registered\":\"2015-09-18T12:59:51Z\",\"location\":{\"lon\":46.564666,\"lat\":53.15213},\"tags\":[\"incididunt\",\"dolore\"],\"friends\":[{\"id\":0,\"name\":\"Jimenez Byers\"},{\"id\":1,\"name\":\"Gabriela Mayer\"}],\"notExist\":\"haha\"}",
		"_timestamp": "2020-01-30T00:00:28.624-05:00",
		"_signature": "98c21b760b61fd4a59af9ea511f75f0338a76881bbd820ed3bb5c14a7dcf3d9847025cdf3aca07e7b448d8a7358d8678298afba8b3d9b16b9bac635457dccde5",
		"_address": "0xf55486314B0C4F032d603B636327ed5c82218688"
	}, {
		"_id": "f8dde1543a7d644fc1ec6e1765c0e694fc96f51625c4d83926b611959188739d",
		"_blockId": "cfc01dc667753185a5635b33ebbff42b452476f15a4f63fceb210aad68dac3b8",
		"_source": "{\"id\":\"5bf1d3fdf6fd4a5c4638f64e\",\"guid\":\"f51b68c5-f274-4ce1-984f-b4fb4d618ff3\",\"isActive\":false,\"age\":28,\"name\":\"Carly Compton\",\"gender\":\"male\",\"registered\":\"2015-09-18T12:59:51Z\",\"location\":{\"lon\":46.564666,\"lat\":53.15213},\"tags\":[\"incididunt\",\"dolore\"],\"friends\":[{\"id\":0,\"name\":\"Jimenez Byers\"},{\"id\":1,\"name\":\"Gabriela Mayer\"}],\"notExist\":\"haha\"}",
		"_timestamp": "2020-01-30T00:00:28.712-05:00",
		"_signature": "98c21b760b61fd4a59af9ea511f75f0338a76881bbd820ed3bb5c14a7dcf3d9847025cdf3aca07e7b448d8a7358d8678298afba8b3d9b16b9bac635457dccde5",
		"_address": "0xf55486314B0C4F032d603B636327ed5c82218688"
	}, {
		"_id": "516ab6ec7db085b0347b7a5f67b36e6654092bc60cc40b2ec3e6370999ef42a3",
		"_blockId": "cfc01dc667753185a5635b33ebbff42b452476f15a4f63fceb210aad68dac3b8",
		"_source": "{\"id\":\"5bf1d3fdf6fd4a5c4638f64e\",\"guid\":\"f51b68c5-f274-4ce1-984f-b4fb4d618ff3\",\"isActive\":false,\"age\":28,\"name\":\"Carly Compton\",\"gender\":\"male\",\"registered\":\"2015-09-18T12:59:51Z\",\"location\":{\"lon\":46.564666,\"lat\":53.15213},\"tags\":[\"incididunt\",\"dolore\"],\"friends\":[{\"id\":0,\"name\":\"Jimenez Byers\"},{\"id\":1,\"name\":\"Gabriela Mayer\"}],\"notExist\":\"haha\"}",
		"_timestamp": "2020-01-30T00:00:28.691-05:00",
		"_signature": "98c21b760b61fd4a59af9ea511f75f0338a76881bbd820ed3bb5c14a7dcf3d9847025cdf3aca07e7b448d8a7358d8678298afba8b3d9b16b9bac635457dccde5",
		"_address": "0xf55486314B0C4F032d603B636327ed5c82218688"
	}]
}
```
`async verifyTransaction(blockId, transationId)` - Obtain a copy of block [Merkle Tree](https://en.wikipedia.org/wiki/Merkle_tree) and verify if the target document adding transaction has been included in the blockchain

Example:
```
const verificationPassed = await blocaceUser.verifyTransaction(queryRes.hits[0]._blockId, queryRes.hits[0]._id)
```

`async getBlockInfo(blockId)` - Get the information of a target block

Example:
```
const blockRes = await blocace.getBlockInfo(queryRes.hits[0]._blockId)
```
Output:
```
{"blockId":"cfc01dc667753185a5635b33ebbff42b452476f15a4f63fceb210aad68dac3b8","lastBlockId":"47e7023f02c4f762d458e674ce1075666e47cafa93a701b6cb88615c6b4f6dc5","blockHeight":1,"totalTransactions":10}
```
`async getBlockchainInfo()` - Get the information of the whole blockchain

Example:
```
const blockchainRes = await blocace.getBlockchainInfo()
```
Output:
```
{"newestBlockId":"cfc01dc667753185a5635b33ebbff42b452476f15a4f63fceb210aad68dac3b8","lastHeight":1,"totalTransactions":11}
```
`async getCollections()` - Get all the collections in the blockchain

Example:
```
const collectionsRes = await blocace.getCollections()
```
Output:
```
{"message":"ok","collections":["default","new1"]}
```
`async getCollection(collectionName)` - Get the information of a certain collection

Example:
```
const collectionRes = await blocace.getCollection('new1')
```
Output:
```
{
	"message": "ok",
	"mapping": {
		"collection": "new1",
		"fields": {
			"age": {
				"encrypted": true,
				"type": "number"
			},
			"gender": {
				"type": "text"
			},
			"guid": {
				"type": "text"
			},
			"id": {
				"type": "text"
			},
			"isActive": {
				"type": "boolean"
			},
			"location": {
				"type": "geopoint"
			},
			"name": {
				"encrypted": true,
				"type": "text"
			},
			"registered": {
				"type": "datetime"
			},
			"tags": {
				"type": "text"
			}
		}
	}
}
```

> Check out [example.js](https://github.com/codingpeasant/blocace-js/blob/master/example.js) for the full usage of the client lib.
