const ethers = require('ethers')
const axios = require('axios')
const CryptoJS = require('crypto-js')

const httpRequestTimeout = 5000 // ms
const keySize = 256
const iterations = 100

class Blocace {
  constructor(wallet, protocol, hostname, port) {
    this.wallet = wallet
    this.hostname = hostname || 'localhost'
    this.port = port || 6899
    this.protocol = protocol || 'http'
  }

  static create(protocol, hostname, port) {
    return new this(new ethers.Wallet.createRandom(), protocol, hostname, port)
  }

  static createFromPrivateKey(privKey, protocol, hostname, port) {
    return new this(new ethers.Wallet(privKey), protocol, hostname, port)
  }

  encryptPrivateKey(pass) {
    try {
      var salt = CryptoJS.lib.WordArray.random(128 / 8)

      var key = CryptoJS.PBKDF2(pass, salt, {
        keySize: keySize / 32,
        iterations: iterations
      })

      var iv = CryptoJS.lib.WordArray.random(128 / 8)

      var encrypted = CryptoJS.AES.encrypt(this.wallet.privateKey, key, {
        iv: iv,
        padding: CryptoJS.pad.Pkcs7,
        mode: CryptoJS.mode.CBC
      })

      // salt, iv will be hex 32 in length
      // append them to the ciphertext for use in decryption
      var transitMessage = salt.toString() + iv.toString() + encrypted.toString()
      return transitMessage
    } catch (exception) {
      throw new Error(exception.message)
    }
  }

  static decryptPrivateKey(encrypted, pass) {
    try {
      var salt = CryptoJS.enc.Hex.parse(encrypted.substr(0, 32))
      var iv = CryptoJS.enc.Hex.parse(encrypted.substr(32, 32))
      var encrypted = encrypted.substring(64)

      var key = CryptoJS.PBKDF2(pass, salt, {
        keySize: keySize / 32,
        iterations: iterations
      })

      var decrypted = CryptoJS.AES.decrypt(encrypted, key, {
        iv: iv,
        padding: CryptoJS.pad.Pkcs7,
        mode: CryptoJS.mode.CBC

      })
      return decrypted.toString(CryptoJS.enc.Utf8)
    } catch (exception) {
      throw new Error(exception.message)
    }
  }

  static verifySignature(rawDocument, signature, address) {
    const docDigest = ethers.utils.keccak256(Buffer.from(rawDocument))
    // for recoveryParam == 0 or 1
    return ethers.utils.recoverAddress(docDigest, '0x' + signature + '00') == address ||
      ethers.utils.recoverAddress(docDigest, '0x' + signature + '01') == address
  }

  getPublicKey() {
    return ethers.utils.computePublicKey(this.wallet.privateKey).substring(4)
  }

  static async createAccount(accountPayload, protocol, hostname, port) {
    // accountPayload.publicKey = this.wallet.getPublicKey().toString('hex')
    const accountRes = await axios.request({
      url: protocol + '://' + hostname + ':' + port + '/account',
      method: 'post',
      timeout: httpRequestTimeout,
      data: accountPayload
    })

    return accountRes
  }

  async updateAccount(accountPayload, address) {
    const accountRes = await axios.request({
      url: this.protocol + '://' + this.hostname + ':' + this.port + '/account/' + address,
      method: 'post',
      timeout: httpRequestTimeout,
      headers: { 'Authorization': 'Bearer ' + this.token },
      data: accountPayload
    })

    return accountRes
  }

  async setAccountReadWrite(permissionPayload, address) {
    const accountRes = await axios.request({
      url: this.protocol + '://' + this.hostname + ':' + this.port + '/setaccountpermission/' + address,
      method: 'post',
      timeout: httpRequestTimeout,
      headers: { 'Authorization': 'Bearer ' + this.token },
      data: permissionPayload
    })

    return accountRes
  }

  async getChallenge() {
    return axios.get(this.protocol + '://' + this.hostname + ':' + this.port + '/jwt/challenge/' + this.wallet.address)
  }

  async getJWT() {
    const challengeResponse = await this.getChallenge()

    const challengeHash = ethers.utils.keccak256(Buffer.from(challengeResponse.data.challenge))
    const sig = this.wallet.signingKey.signDigest(challengeHash)

    const jwt = await axios.post(this.protocol + '://' + this.hostname + ':' + this.port + '/jwt', {
      'address': this.wallet.address,
      'signature': sig.r.substring(2) + sig.s.substring(2)
    })

    this.token = jwt.data.token
    return jwt.data.token
  }

  async getAccount(address) {
    const accountRes = await axios.request({
      url: this.protocol + '://' + this.hostname + ':' + this.port + '/account/' + address,
      method: 'get',
      timeout: httpRequestTimeout,
      headers: { 'Authorization': 'Bearer ' + this.token }
    })

    return accountRes.data
  }

  async createCollection(collectionPayload) {
    const collectionCreationRes = await axios.request({
      url: this.protocol + '://' + this.hostname + ':' + this.port + '/collection',
      method: 'post',
      timeout: httpRequestTimeout,
      headers: { 'Authorization': 'Bearer ' + this.token },
      data: collectionPayload
    })

    return collectionCreationRes.data
  }

  async signAndPutDocument(document, collection) {
    const docHash = ethers.utils.keccak256(Buffer.from(JSON.stringify(document)))
    const sig = this.wallet.signingKey.signDigest(docHash)

    const putDocRes = await axios.request({
      url: this.protocol + '://' + this.hostname + ':' + this.port + '/document/' + collection,
      method: 'post',
      timeout: httpRequestTimeout,
      headers: { 'Authorization': 'Bearer ' + this.token },
      data: {
        'rawDocument': JSON.stringify(document),
        'signature': sig.r.substring(2) + sig.s.substring(2)
      }
    })

    return putDocRes.data
  }

  // WARNING: this makes the document unverifiable
  async putDocumentBulk(documents, collection) {
    const putDocRes = await axios.request({
      url: this.protocol + '://' + this.hostname + ':' + this.port + '/bulk/' + collection,
      method: 'post',
      timeout: httpRequestTimeout,
      headers: { 'Authorization': 'Bearer ' + this.token },
      data: documents
    })

    return putDocRes.data
  }

  async query(queryPayload, collection) {
    const queryRes = await axios.request({
      url: this.protocol + '://' + this.hostname + ':' + this.port + '/search/' + collection,
      method: 'post',
      timeout: httpRequestTimeout,
      headers: { 'Authorization': 'Bearer ' + this.token },
      data: queryPayload
    })

    return queryRes.data
  }

  async verifyTransaction(blockId, transationId) {
    const verificationPathRes = await axios.request({
      url: this.protocol + '://' + this.hostname + ':' + this.port + '/verification/' + blockId + '/' + transationId,
      method: 'get',
      timeout: httpRequestTimeout,
      headers: { 'Authorization': 'Bearer ' + this.token }
    })

    const verificationPath = verificationPathRes.data.verificationPath
    var keys = Object.keys(verificationPath)
    var hashData = Buffer.from(transationId, 'hex')

    for (let i = keys.length - 1; i > 0; i--) {
      var secondHash = Buffer.from(verificationPath[keys[i]], 'hex')
      if (keys[i] % 2 === 0) { // right child
        var prevHashes = Buffer.concat([hashData, secondHash])
        hashData = Buffer.from(ethers.utils.keccak256(prevHashes).substring(2), 'hex')
      } else {
        prevHashes = Buffer.concat([secondHash, hashData])
        hashData = Buffer.from(ethers.utils.keccak256(prevHashes).substring(2), 'hex')
      }
    }

    return hashData.equals(Buffer.from(verificationPath['0'], 'hex'))
  }

  async getBlockInfo(blockId) {
    const blockInfoRes = await axios.request({
      url: this.protocol + '://' + this.hostname + ':' + this.port + '/block/' + blockId,
      method: 'get',
      timeout: httpRequestTimeout,
      headers: { 'Authorization': 'Bearer ' + this.token }
    })

    return blockInfoRes.data
  }

  async getBlockchainInfo() {
    const blockchainRes = await axios.request({
      url: this.protocol + '://' + this.hostname + ':' + this.port + '/info',
      method: 'get',
      timeout: httpRequestTimeout,
      headers: { 'Authorization': 'Bearer ' + this.token }
    })

    return blockchainRes.data
  }

  async getCollections() {
    const collectionsRes = await axios.request({
      url: this.protocol + '://' + this.hostname + ':' + this.port + '/collections',
      method: 'get',
      timeout: httpRequestTimeout,
      headers: { 'Authorization': 'Bearer ' + this.token }
    })

    return collectionsRes.data
  }

  async getCollection(collectionName) {
    const collectionRes = await axios.request({
      url: this.protocol + '://' + this.hostname + ':' + this.port + '/collection/' + collectionName,
      method: 'get',
      timeout: httpRequestTimeout,
      headers: { 'Authorization': 'Bearer ' + this.token }
    })

    return collectionRes.data
  }
}

module.exports = Blocace