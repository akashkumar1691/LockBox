package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	userlib "github.com/cs161-staff/project2-userlib"

	// Likewise, useful for debugging, etc.
	"encoding/hex"

	// Useful for string mainpulation.
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"
)

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.

// This function can be safely deleted!
func someUsefulThings() {
	// Creates a random UUID
	f := userlib.UUIDNew()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Works well with Go structures!
	d, _ := userlib.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g userlib.UUID
	userlib.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// errors.New(...) creates an error type!
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)

	// Useful for string interpolation.
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// User is the structure definition for a user record.
type UserFileInfo struct{
	FileEncKey []byte
	FileAuthKey []byte
	MetaEncKey []byte
	MetaAuthKey []byte
	OwnersUsername string //to verify empty file and update fileInfo after revokation
	FileUUID userlib.UUID
	MetaUUID userlib.UUID
	PermissionMapUUID userlib.UUID
	ParentSharer string
	FromOwner bool
	IsOwner bool
}

type User struct {
	Username string
	DSPrivKey userlib.DSSignKey
	PKEPrivKey userlib.PKEDecKey
	EncKey []byte
	AuthKey []byte
	UUID userlib.UUID
	FatherKey []byte
	UUIDNil userlib.UUID

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type Metadata struct{
	LastAppend userlib.UUID
	SharedTree map[string][]string
	SharedMap map[string]bool
	AppendsListSize int
}


type AuthEncUser struct{
	Signer string
	EncData []byte
	HMAC []byte
	EncryptedSymEncKey []byte
	KeyHMAC []byte
	OwnersEncryptedKey []byte
	OwnrEncdKeyHMAC []byte
}

type AuthEncData struct {
	EncData []byte
	HMAC    []byte
	Prev    []byte
	PrevHMAC []byte

}

func InitUser(username string, password string) (userdataptr *User, err error) {
	if username == ""{return nil, errors.New("Cannot input empty username")}
	userBytes := []byte(username)
	userHash := userlib.Hash(userBytes)
	passwordBytes := []byte(password)
	fatherKey := userlib.Argon2Key(passwordBytes,userBytes,64)
	StructHash, err := userlib.HashKDF(fatherKey[0:16], []byte("encrypt"))
	StructEncrKey := StructHash[0:16]
	StructIV := userlib.RandomBytes(16)
	StructAuthKey := StructHash[16:32]
	userUUID, err := userlib.UUIDFromBytes(StructHash[32:48])
	if err != nil {return nil, err}
	var zero_bytes []byte
	for i:=0; i < 16; i++{
		zero_bytes = append(zero_bytes, 0x00)
	}
	UUIDNil,err := userlib.UUIDFromBytes(zero_bytes)
	if err !=nil{return nil,err}

	userCheck,err := userlib.UUIDFromBytes(userHash)
	if err != nil {return nil, err}
	_,ok := userlib.DatastoreGet(userCheck)
	if ok {return nil,errors.New("User Already Exists")}
	userlib.DatastoreSet(userCheck,userHash)



	var userdata User
	userdata.Username = username
	userdata.EncKey = StructEncrKey
	userdata.AuthKey = StructAuthKey
	userdata.UUID = userUUID
	userdata.FatherKey = fatherKey
	userdata.UUIDNil = UUIDNil

	DSprivate, DSpublic, err := userlib.DSKeyGen()
	if err != nil {return nil, err}
	userdata.DSPrivKey = DSprivate
	err = userlib.KeystoreSet(username+"DS", DSpublic)
	if err != nil {return nil, err}

	PKEpublic, PKEprivate, err := userlib.PKEKeyGen()
	if err != nil {return nil, err}
	userdata.PKEPrivKey = PKEprivate
	err = userlib.KeystoreSet(username+"PKE",PKEpublic)
	if err != nil {return nil, err}


	marshalStruct, err := userlib.Marshal(userdata)
	if err != nil {return nil, err}
	EncMarshalStruct := userlib.SymEnc(StructEncrKey,StructIV,marshalStruct)
	userMAC, err := userlib.HMACEval(StructAuthKey,EncMarshalStruct )
	if err != nil {return nil, err}
	var AuthUserData AuthEncUser
	AuthUserData.EncData = EncMarshalStruct
	AuthUserData.HMAC = userMAC
	marshalAuthStruct, err := userlib.Marshal(AuthUserData)
	if err != nil {return nil, err}
	userlib.DatastoreSet(userUUID,marshalAuthStruct)

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	userBytes := []byte(username)
	passwordBytes := []byte(password)
	fatherKey := userlib.Argon2Key(passwordBytes,userBytes,64)
	StructHash, err := userlib.HashKDF(fatherKey[0:16], []byte("encrypt"))
	StructDecKey := StructHash[0:16]
	StructHMAC := StructHash[16:32]
	userUUID, err := userlib.UUIDFromBytes(StructHash[32:48])
	if err != nil {return nil, err}

	marshalAuthStruct, ok := userlib.DatastoreGet(userUUID)
	if !ok{return nil, errors.New("User Does Not Exist")}
	var AuthUserData AuthEncUser
	err = userlib.Unmarshal(marshalAuthStruct, &AuthUserData)
	if err != nil{return nil,err}
	EncMarshalStruct := AuthUserData.EncData
	userMAC, err := userlib.HMACEval(StructHMAC,EncMarshalStruct )
	if err != nil {return nil, err}
	if userlib.HMACEqual(userMAC, AuthUserData.HMAC) == false{return nil, errors.New("Integrity is compromised")}
	marshalStruct := userlib.SymDec(StructDecKey,EncMarshalStruct)
	var userdata User
	err = userlib.Unmarshal(marshalStruct, &userdata)
	if err != nil {return nil, err}
	userdataptr = &userdata

	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	var fileEncKey []byte
	var fileAuthKey []byte
	var fileEncIv,metaEncIv, fileInfoEncIV []byte = userlib.RandomBytes(16),userlib.RandomBytes(16),userlib.RandomBytes(16)
	var metaEncKey []byte
	var metaAuthKey []byte
	var metaUUID, fileUUID, fileInfoUUID userlib.UUID
	var userFileInfo UserFileInfo
	var fileInfoEncKey, fileInfoAuthKey []byte

	//Create instance of metadata struct
	var meta Metadata

	fileInfoUUIDHASH,err := userlib.HashKDF(userdata.FatherKey[32:48],[]byte(filename))
	if err != nil{return err}
	fileInfoUUID,err = userlib.UUIDFromBytes(fileInfoUUIDHASH)
	if err != nil{return err}

	//check if file is new or overwriting

	if _, ok := userlib.DatastoreGet(fileInfoUUID); !ok {
		//Generate encKey, authKey, and UUID for file (newUUID() and randomByteGenerator)
		fileEncKey = userlib.RandomBytes(16)
		fileAuthKey = userlib.RandomBytes(16)
		fileInfoKeys, err := userlib.HashKDF(userdata.FatherKey[16:32],[]byte(filename))
		if err != nil {return err}
		fileInfoEncKey = fileInfoKeys[0:16]
		fileInfoAuthKey = fileInfoKeys[16:32]
		metaUUID, fileUUID = userlib.UUIDNew(), userlib.UUIDNew()
		if err != nil{return err}

		meta.LastAppend = fileUUID
		//Set number of nodes in linked list to 0
		meta.AppendsListSize = 0
		//Generate empty instance of SharedTree
		meta.SharedTree = make(map[string][]string)
		meta.SharedMap = make(map[string]bool)
		//Create enc and auth keys and UUID for metadata (newUUID() and randomByteGenerator)
		metaEncKey  = userlib.RandomBytes(16)
		metaAuthKey = userlib.RandomBytes(16)
		//Generate permissionMap
		permissionMap := make(map[string][]byte)
		//Generate uuid for permission map
		var permissionMapUUID userlib.UUID = userlib.UUIDNew()
		//Map filename to metaUUID, fileUUID, PermissionMapUUID, metaKeys, and filekeys in userdata.UserFileInfo
		userFileInfo.FileEncKey = fileEncKey
		userFileInfo.FileAuthKey = fileAuthKey
		userFileInfo.MetaEncKey = metaEncKey
		userFileInfo.MetaAuthKey = metaAuthKey
		userFileInfo.OwnersUsername = userdata.Username
		userFileInfo.FileUUID = fileUUID
		userFileInfo.MetaUUID = metaUUID
		userFileInfo.PermissionMapUUID = permissionMapUUID
		userFileInfo.FromOwner = false
		userFileInfo.IsOwner = true
		userFileInfo.ParentSharer = ""



		//Marshal and datastoreSet permissionMap
		marshalPMap, err := userlib.Marshal(permissionMap)
		if err != nil {return err}
		userlib.DatastoreSet(permissionMapUUID,marshalPMap)

		//marshal,encrypt,auth, marshal and datastoreSet fileInfo
		marshFileInfo, err := userlib.Marshal(userFileInfo)
		if err != nil{return err}
		encMarshFileInfo := userlib.SymEnc(fileInfoEncKey, fileInfoEncIV, marshFileInfo)
		fileInfoHMAC, err := userlib.HMACEval(fileInfoAuthKey,encMarshFileInfo)
		if err != nil{return err}
		var authEncFileInfo AuthEncData
		authEncFileInfo.HMAC, authEncFileInfo.EncData = fileInfoHMAC, encMarshFileInfo
		marshAuthEncFileInfo, err := userlib.Marshal(authEncFileInfo)
		if err != nil{return err}
		userlib.DatastoreSet(fileInfoUUID,marshAuthEncFileInfo)


	}else{
		metaPtr,_,fileInfo, err := LoadFileHelper(filename, userdata, "storeFile")
		if err != nil {return err}

		fileEncKey = fileInfo.FileEncKey
		fileAuthKey = fileInfo.FileAuthKey
		metaUUID, fileUUID = fileInfo.MetaUUID, fileInfo.FileUUID

		metaEncKey  = fileInfo.MetaEncKey
		metaAuthKey = fileInfo.MetaAuthKey

		metaPtr.LastAppend = fileInfo.FileUUID
		metaPtr.AppendsListSize = 0

		meta = *metaPtr
	}

	//Marshal,encrypt,authenticate,marshal and datastoreSet metadata
	marshalMeta, err := userlib.Marshal(meta)
	if err != nil {return err}
	var encMarshalMeta []byte = userlib.SymEnc(metaEncKey, metaEncIv, marshalMeta)
	authMeta, err := userlib.HMACEval(metaAuthKey,encMarshalMeta)
	if err != nil{return err}
	var authEncMeta AuthEncData
	authEncMeta.EncData, authEncMeta.HMAC = encMarshalMeta,authMeta
	dataStoreMeta, err := userlib.Marshal(authEncMeta)
	if err != nil {return err}
	userlib.DatastoreSet(metaUUID,dataStoreMeta)

	//Marshal,encrypt,authenticate,marshal and datastoreSet file
	marshalFile, err := userlib.Marshal(content)
	if err != nil{return err}
	var encMarshalFile []byte = userlib.SymEnc(fileEncKey, fileEncIv, marshalFile)
	authFile, err := userlib.HMACEval(fileAuthKey,encMarshalFile)
	if err != nil {return err}
	marshalUUID, err := userlib.Marshal(userdata.UUIDNil)
	if err != nil{return err}
	var encMarshUUID []byte = userlib.SymEnc(fileEncKey,userlib.RandomBytes(16), marshalUUID)
	authUUID, err := userlib.HMACEval(fileAuthKey,encMarshUUID)
	if err != nil {return err}
	var AuthEncContent AuthEncData
	AuthEncContent.EncData, AuthEncContent.HMAC= encMarshalFile,authFile
	AuthEncContent.Prev,AuthEncContent.PrevHMAC = encMarshUUID,authUUID
	dataStoreFile, err := userlib.Marshal(AuthEncContent)
	if err != nil {return err}
	userlib.DatastoreSet(fileUUID,dataStoreFile)

	//Marshal,encrypt,authenticate,marshal and datastoreSet userStruct
	marshalUser, err := userlib.Marshal(*userdata)
	if err != nil {return err}
	var userEncIv []byte = userlib.RandomBytes(16)
	var encMarshalUser []byte = userlib.SymEnc(userdata.EncKey, userEncIv, marshalUser)
	authUser, err := userlib.HMACEval(userdata.AuthKey,encMarshalUser)
	if err != nil {return err}
	var authEncUser AuthEncUser
	authEncUser.EncData, authEncUser.HMAC = encMarshalUser,authUser
	dataStoreUser, err := userlib.Marshal(authEncUser)
	if err != nil {return err}
	userlib.DatastoreSet(userdata.UUID,dataStoreUser)

	return
}

func LoadFileHelper(filename string, userdata *User,caller string) (metaPtr *Metadata, permissionMapPtr *map[string][]byte, userfileinfoptr *UserFileInfo, err error){


	fileInfoUUIDHASH,err := userlib.HashKDF(userdata.FatherKey[32:48],[]byte(filename))
	if err != nil{return nil,nil,nil,err}
	fileInfoUUID,err := userlib.UUIDFromBytes(fileInfoUUIDHASH)
	if err != nil{return nil,nil,nil,err}
	marshEncInfo, ok := userlib.DatastoreGet(fileInfoUUID)
	if !ok{return nil,nil,nil,errors.New("fileInfo not found in datastore")}
	var authEncStruct AuthEncData
	err = userlib.Unmarshal(marshEncInfo,&authEncStruct)
	if err != nil{return nil,nil,nil,err}

	fileInfoKeys, err := userlib.HashKDF(userdata.FatherKey[16:32],[]byte(filename))
	if err != nil{return nil,nil,nil,err}
	fileInfoEncKey := fileInfoKeys[0:16]
	fileInfoAuthKey := fileInfoKeys[16:32]

	newHmac,err := userlib.HMACEval(fileInfoAuthKey,authEncStruct.EncData)
	if err != nil{return nil,nil,nil,err}
	userlib.HMACEqual(authEncStruct.HMAC,newHmac)
	marshInfo := userlib.SymDec(fileInfoEncKey,authEncStruct.EncData)
	var info UserFileInfo
	err = userlib.Unmarshal(marshInfo,&info)
	if err != nil{return nil,nil,nil,err}

	verifyKey, ok :=  userlib.KeystoreGet(info.OwnersUsername+"DS")
	if !ok{return nil,nil,nil,errors.New("")}
	marshMap, ok :=userlib.DatastoreGet(info.PermissionMapUUID)
	if !ok{return nil,nil,nil,errors.New("")}
	var permissionMap map[string][]byte
	err = userlib.Unmarshal(marshMap,&permissionMap)
	if err != nil{return nil,nil,nil,err}


	var marshEncMeta []byte
	marshEncMeta, ok = userlib.DatastoreGet(info.MetaUUID)
	if !ok{
		//update userInfo if empty
		if info.IsOwner{return nil,nil,nil,errors.New( ";metaData not found before update even though fileowner")}

		if marshEncInfo, ok := permissionMap[userdata.Username]; !ok{return nil,nil,nil,errors.New("")
		}else{
			var encUpdateInfo AuthEncUser
			err = userlib.Unmarshal(marshEncInfo,&encUpdateInfo)
			if err != nil {return nil,nil,nil,err}
			err = userlib.DSVerify(verifyKey,encUpdateInfo.EncData,encUpdateInfo.HMAC)
			if err != nil {return nil,nil,nil,err}
			err = userlib.DSVerify(verifyKey,encUpdateInfo.EncryptedSymEncKey,encUpdateInfo.KeyHMAC)
			if err != nil {return nil,nil,nil,err}
			decKey := userdata.PKEPrivKey

			Key, err := userlib.PKEDec(decKey,encUpdateInfo.EncryptedSymEncKey)
			if err != nil {return nil,nil,nil,err}
			marshUpdateInfo := userlib.SymDec(Key,encUpdateInfo.EncData)
			var updateInfo UserFileInfo
			err = userlib.Unmarshal(marshUpdateInfo,&updateInfo)
			if err != nil {return nil,nil,nil,err}

			info.FileEncKey = updateInfo.FileEncKey
			info.FileAuthKey = updateInfo.FileAuthKey
			info.MetaEncKey = updateInfo.MetaEncKey
			info.MetaAuthKey = updateInfo.MetaAuthKey
			info.FileUUID = updateInfo.FileUUID
			info.MetaUUID = updateInfo.MetaUUID

			//marshal,encrypt,auth, marshal and datastoreSet fileInfo
			marshFileInfo, err := userlib.Marshal(info)
			if err != nil{return nil,nil,nil,err}
			encMarshFileInfo := userlib.SymEnc(fileInfoEncKey, userlib.RandomBytes(16), marshFileInfo)
			fileInfoHMAC, err := userlib.HMACEval(fileInfoAuthKey,encMarshFileInfo)
			if err != nil{return nil,nil,nil,err}
			var authEncFileInfo AuthEncData
			authEncFileInfo.HMAC, authEncFileInfo.EncData = fileInfoHMAC, encMarshFileInfo
			marshAuthEncFileInfo, err := userlib.Marshal(authEncFileInfo)
			if err != nil{return nil,nil,nil,err}
			userlib.DatastoreSet(fileInfoUUID,marshAuthEncFileInfo)

			marshEncMeta, ok = userlib.DatastoreGet(info.MetaUUID)
			if !ok {return nil,nil,nil,errors.New("")}


		}}

	var authEncMeta AuthEncData
	err = userlib.Unmarshal(marshEncMeta, &authEncMeta)
	if err != nil{return nil,nil,nil,err}
	newHmac,err = userlib.HMACEval(info.MetaAuthKey,authEncMeta.EncData)
	if err != nil{return nil,nil,nil,err}
	if !userlib.HMACEqual(authEncMeta.HMAC,newHmac){return nil,nil,nil,errors.New("")}
	marshMeta := userlib.SymDec(info.MetaEncKey,authEncMeta.EncData)
	var meta Metadata
	err = userlib.Unmarshal(marshMeta,&meta)
	if err != nil{return nil,nil,nil,err}
	//load return value pointers
	metaPtr = &meta
	permissionMapPtr = &permissionMap
	userfileinfoptr = &info
	err = nil

	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {

	fileInfoUUIDHASH,err := userlib.HashKDF(userdata.FatherKey[32:48],[]byte(filename))
	if err != nil{return err}
	fileInfoUUID,err := userlib.UUIDFromBytes(fileInfoUUIDHASH)
	if err != nil{return err}
	marshEncInfo, ok := userlib.DatastoreGet(fileInfoUUID)
	if !ok{return errors.New("fileInfo not found in datastore")}
	var authEncStruct AuthEncData
	err = userlib.Unmarshal(marshEncInfo,&authEncStruct)
	if err != nil{return err}

	fileInfoKeys, err := userlib.HashKDF(userdata.FatherKey[16:32],[]byte(filename))
	if err != nil {return err}
	fileInfoEncKey := fileInfoKeys[0:16]
	fileInfoAuthKey := fileInfoKeys[16:32]

	newHmac,err := userlib.HMACEval(fileInfoAuthKey,authEncStruct.EncData)
	if err != nil{return err}
	userlib.HMACEqual(authEncStruct.HMAC,newHmac)
	marshInfo := userlib.SymDec(fileInfoEncKey,authEncStruct.EncData)
	var info UserFileInfo
	err = userlib.Unmarshal(marshInfo,&info)
	if err != nil{return err}
	var marshEncMeta []byte
	marshEncMeta, ok = userlib.DatastoreGet(info.MetaUUID)
	if !ok{

			if info.IsOwner{return errors.New( ";metaData not found before update even though fileowner")}
			verifyKey, ok :=  userlib.KeystoreGet(info.OwnersUsername+"DS")
			if !ok{return errors.New("")}
			marshMap, ok :=userlib.DatastoreGet(info.PermissionMapUUID)
			if !ok{return errors.New("")}
			var permissionMap map[string][]byte
			err = userlib.Unmarshal(marshMap,&permissionMap)
			if err != nil{return err}
			if marshEncInfo, ok := permissionMap[userdata.Username]; !ok{
				return errors.New("")
				//update userInfo if empty
			}else{
				var encUpdateInfo AuthEncUser
				err = userlib.Unmarshal(marshEncInfo,&encUpdateInfo)
				if err != nil {return err}
				err = userlib.DSVerify(verifyKey,encUpdateInfo.EncData,encUpdateInfo.HMAC)
				if err != nil {return err}
				err = userlib.DSVerify(verifyKey,encUpdateInfo.EncryptedSymEncKey,encUpdateInfo.KeyHMAC)
				if err != nil {return err}
				decKey := userdata.PKEPrivKey

				Key, err := userlib.PKEDec(decKey,encUpdateInfo.EncryptedSymEncKey)
				if err != nil {return err}
				marshUpdateInfo := userlib.SymDec(Key,encUpdateInfo.EncData)
				var updateInfo UserFileInfo
				err = userlib.Unmarshal(marshUpdateInfo,&updateInfo)
				if err != nil {return err}

				info.FileEncKey = updateInfo.FileEncKey
				info.FileAuthKey = updateInfo.FileAuthKey
				info.MetaEncKey = updateInfo.MetaEncKey
				info.MetaAuthKey = updateInfo.MetaAuthKey
				info.FileUUID = updateInfo.FileUUID
				info.MetaUUID = updateInfo.MetaUUID

				//marshal,encrypt,auth, marshal and datastoreSet fileInfo
				marshFileInfo, err := userlib.Marshal(info)
				if err != nil{return err}
				encMarshFileInfo := userlib.SymEnc(fileInfoEncKey, userlib.RandomBytes(16), marshFileInfo)
				fileInfoHMAC, err := userlib.HMACEval(fileInfoAuthKey,encMarshFileInfo)
				if err != nil{return err}
				var authEncFileInfo AuthEncData
				authEncFileInfo.HMAC, authEncFileInfo.EncData = fileInfoHMAC, encMarshFileInfo
				marshAuthEncFileInfo, err := userlib.Marshal(authEncFileInfo)
				if err != nil{return err}
				userlib.DatastoreSet(fileInfoUUID,marshAuthEncFileInfo)

				marshEncMeta, ok = userlib.DatastoreGet(info.MetaUUID)
				if !ok {return errors.New("")}


		}}

	var authEncMeta AuthEncData
	err = userlib.Unmarshal(marshEncMeta, &authEncMeta)
	if err != nil{return err}
	newHmac,err = userlib.HMACEval(info.MetaAuthKey,authEncMeta.EncData)
	if err != nil{return err}
	if !userlib.HMACEqual(authEncMeta.HMAC,newHmac){return errors.New("")}
	marshMeta := userlib.SymDec(info.MetaEncKey,authEncMeta.EncData)
	var meta Metadata
	err = userlib.Unmarshal(marshMeta,&meta)
	if err != nil{return err}

	meta.AppendsListSize = meta.AppendsListSize+1
	prev := meta.LastAppend
	meta.LastAppend = userlib.UUIDNew()

	//marshal,encrypt,authenticate,marshal metadata(updated listsize)
	metaEncKey := info.MetaEncKey
	metaEncIv := userlib.RandomBytes(16)
	metaAuthKey := info.MetaAuthKey
	marshalMeta,err := userlib.Marshal(meta)
	if err != nil {return err}
	var encMarshalMeta []byte = userlib.SymEnc(metaEncKey, metaEncIv, marshalMeta)
	authMeta, err := userlib.HMACEval(metaAuthKey,encMarshalMeta)
	if err != nil {return err}
	authEncMeta.EncData, authEncMeta.HMAC = encMarshalMeta,authMeta
	dataStoreMeta,err := userlib.Marshal(authEncMeta)
	if err != nil {return err}
	userlib.DatastoreSet(info.MetaUUID,dataStoreMeta)

	//marshal,encrypt,authenticate,marshal append
	marshalApnd, err := userlib.Marshal(content)
	if err != nil {return err}
	var encMarshalApnd []byte = userlib.SymEnc(info.FileEncKey, userlib.RandomBytes(16), marshalApnd)
	authApnd, err := userlib.HMACEval(info.FileAuthKey,encMarshalApnd)
	if err != nil {return err}
	marshPrev,err := userlib.Marshal(prev)
	var encMarshUUID []byte = userlib.SymEnc(info.FileEncKey,userlib.RandomBytes(16), marshPrev)
	authUUID, err := userlib.HMACEval(info.FileAuthKey,encMarshUUID)
	if err != nil {return err}
	var AuthEncData AuthEncData
	AuthEncData.EncData, AuthEncData.HMAC = encMarshalApnd,authApnd
	AuthEncData.Prev,AuthEncData.PrevHMAC = encMarshUUID,authUUID
	dataStoreApnd, err := userlib.Marshal(AuthEncData)
	if err != nil {return err}
	userlib.DatastoreSet(meta.LastAppend,dataStoreApnd)
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	metaPtr, _, fileInfoPtr, err := LoadFileHelper(filename, userdata,"LoadFile")
	if err != nil {return nil,err}
	marshEncAuthFile, ok := userlib.DatastoreGet(fileInfoPtr.FileUUID)
	if !ok{return nil, errors.New("File Not Found in DataStore")}


	//verify and decrypt filedata
	var authEncFile AuthEncData
	err = userlib.Unmarshal(marshEncAuthFile,&authEncFile)
	if err != nil {return nil,err}
	compar,err := userlib.HMACEval(fileInfoPtr.FileAuthKey,authEncFile.EncData)
	if err != nil {return nil,err}
	if !userlib.HMACEqual(authEncFile.HMAC,compar){return nil, errors.New("HMAC unable to verify; integrity compromised")}
	marshFile := userlib.SymDec(fileInfoPtr.FileEncKey,authEncFile.EncData)
	var ogFile []byte
	err = userlib.Unmarshal(marshFile,&ogFile)
	if err != nil {return nil,err}

	//check if number of appends is zero
	if metaPtr.AppendsListSize == 0 {return ogFile,nil}

	var apndUUID userlib.UUID = metaPtr.LastAppend
	var fileSoFar []byte = make([]byte,0)
	for i := 0; i <= metaPtr.AppendsListSize; i++ {
		marshEncApnd, ok := userlib.DatastoreGet(apndUUID)
		if !ok{return nil,errors.New("apnd not found")}
		var encAuthApnd AuthEncData
		err = userlib.Unmarshal(marshEncApnd,&encAuthApnd)
		newHmac,err := userlib.HMACEval(fileInfoPtr.FileAuthKey,encAuthApnd.EncData)
		if err != nil{return nil,err}
		if !userlib.HMACEqual(encAuthApnd.HMAC,newHmac){return nil, errors.New("integrity of append compromised")}
		marshApnd := userlib.SymDec(fileInfoPtr.FileEncKey,encAuthApnd.EncData)
		var apnd []byte
		err = userlib.Unmarshal(marshApnd,&apnd)
		if err != nil {return nil,err}
		for _,b := range fileSoFar{
			apnd =	append(apnd,b)
		}
		fileSoFar= apnd
		newHmac,err = userlib.HMACEval(fileInfoPtr.FileAuthKey,encAuthApnd.Prev)
		if err != nil{return nil,err}
		if !userlib.HMACEqual(encAuthApnd.PrevHMAC,newHmac){return nil, errors.New("integrity of prevAppendUUID compromised")}
		marshPrev := userlib.SymDec(fileInfoPtr.FileEncKey,encAuthApnd.Prev)
		err = userlib.Unmarshal(marshPrev,&apndUUID)
		if err != nil{return nil,err}
		if apndUUID.String() == userdata.UUIDNil.String(){return fileSoFar,nil}


	}
	return ogFile, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr userlib.UUID, err error) {

	userBytes := []byte(recipientUsername)
	userHash := userlib.Hash(userBytes)
	userCheck,err := userlib.UUIDFromBytes(userHash)
	if err != nil {return userlib.UUIDNew(), err}
	_,ok := userlib.DatastoreGet(userCheck)
	if !ok {return userlib.UUIDNew(),errors.New("User Doesn't Exist")}
	//loadFileHelper
	metaPtr, permissionMapPtr, fileInfoPtr, err := LoadFileHelper(filename, userdata, "CreateInvitation")
	if err != nil {return userlib.UUIDNew(),err}
	metaPtr.SharedMap[recipientUsername] = true
	//Create new instance of UserFileInfo struct and copy all info except sharers Username which is parent branch
	var newInfo UserFileInfo
	newInfo.FileEncKey = fileInfoPtr.FileEncKey
	newInfo.FileAuthKey = fileInfoPtr.FileAuthKey
	newInfo.MetaEncKey = fileInfoPtr.MetaEncKey
	newInfo.MetaAuthKey = fileInfoPtr.MetaAuthKey
	newInfo.OwnersUsername = fileInfoPtr.OwnersUsername
	newInfo.IsOwner = false
	newInfo.FileUUID = fileInfoPtr.FileUUID
	newInfo.MetaUUID = fileInfoPtr.MetaUUID
	newInfo.PermissionMapUUID = fileInfoPtr.PermissionMapUUID

	//Add child with shared’s username to metadata.sharedTree with parent sharer as parent
	switch{ case fileInfoPtr.IsOwner:
		newInfo.FromOwner = true
		newInfo.ParentSharer = fileInfoPtr.OwnersUsername
		metaPtr.SharedTree[recipientUsername] = make([]string,0)
	case fileInfoPtr.FromOwner:
		newInfo.FromOwner = false
		newInfo.ParentSharer = userdata.Username
		list := metaPtr.SharedTree[newInfo.ParentSharer]
		metaPtr.SharedTree[newInfo.ParentSharer] = append(list,recipientUsername)
	default:
		newInfo.FromOwner = false
		newInfo.ParentSharer = fileInfoPtr.ParentSharer
		list := metaPtr.SharedTree[newInfo.ParentSharer]
		metaPtr.SharedTree[newInfo.ParentSharer] = append(list,recipientUsername)
	}

	//Marshal userfileInfo struct and encrypt it with shared’s public key,
	// enc and auth file info with sym key and sign and pke symkey
	//
	marshFileInfo, err := userlib.Marshal(newInfo)
	if err != nil {return userlib.UUIDNew(),err}
	var newFileInfoEncKey []byte = userlib.RandomBytes(16)
	var newFileInfoEncIv []byte = userlib.RandomBytes(16)

	encFileInfo := userlib.SymEnc(newFileInfoEncKey,newFileInfoEncIv,marshFileInfo)
	authFileInfo,err := userlib.DSSign(userdata.DSPrivKey, encFileInfo)
	if err != nil {return userlib.UUIDNew(), err}
	sharedPubKey, ok := userlib.KeystoreGet(recipientUsername+"PKE")
	if !ok{return userlib.UUIDNew(),errors.New("")}
	encryptedSymEncKey, err := userlib.PKEEnc(sharedPubKey,newFileInfoEncKey)
	if err != nil {return userlib.UUIDNew(),err}
	authEncryptedKey, err := userlib.DSSign(userdata.DSPrivKey,encryptedSymEncKey)
	if err != nil {return userlib.UUIDNew(),err}
	var authEncNewInfo AuthEncUser
	authEncNewInfo.EncData, authEncNewInfo.HMAC = encFileInfo, authFileInfo
	authEncNewInfo.EncryptedSymEncKey, authEncNewInfo.KeyHMAC = encryptedSymEncKey, authEncryptedKey

	//give owner access to PMap values
	ownerPubKey, ok := userlib.KeystoreGet(fileInfoPtr.OwnersUsername+"PKE")
	if !ok{return userlib.UUIDNew(),errors.New("")}
	ownerEncryptedKey, err := userlib.PKEEnc(ownerPubKey,newFileInfoEncKey)
	if err != nil {return userlib.UUIDNew(),err}
	ownrEncdKeyHMAC, err := userlib.DSSign(userdata.DSPrivKey,ownerEncryptedKey)
	if err != nil {return userlib.UUIDNew(),err}
	authEncNewInfo.OwnersEncryptedKey = ownerEncryptedKey
	authEncNewInfo.Signer = userdata.Username
	authEncNewInfo.OwnrEncdKeyHMAC = ownrEncdKeyHMAC
	mapVal,err := userlib.Marshal(authEncNewInfo)
	if err != nil {return userlib.UUIDNew(),err}
	//Map shared’s username to AuthEncStruct in permissionMap
	(*permissionMapPtr)[recipientUsername] = mapVal


	//Marshal and datastoreSet permissionMap
	marshalPMap, err := userlib.Marshal(*permissionMapPtr)
	if err != nil {return userlib.UUIDNew(),err}
	userlib.DatastoreSet(fileInfoPtr.PermissionMapUUID,marshalPMap)



	//marshal,encrypt,authenticate,marshal metadata(updated sharedTree)
	metaEncKey := fileInfoPtr.MetaEncKey
	metaEncIv := userlib.RandomBytes(16)
	metaAuthKey := fileInfoPtr.MetaAuthKey
	marshalMeta,err := userlib.Marshal(*metaPtr)
	if err != nil {return userlib.UUIDNew(),err}
	var encMarshalMeta []byte = userlib.SymEnc(metaEncKey, metaEncIv, marshalMeta)
	authMeta, err := userlib.HMACEval(metaAuthKey,encMarshalMeta)
	if err != nil {return userlib.UUIDNew(),err}
	var authEncMeta AuthEncData
	authEncMeta.EncData, authEncMeta.HMAC = encMarshalMeta,authMeta
	dataStoreMeta,err := userlib.Marshal(authEncMeta)
	if err != nil {return userlib.UUIDNew(),err}
	userlib.DatastoreSet(fileInfoPtr.MetaUUID,dataStoreMeta)




	return fileInfoPtr.PermissionMapUUID, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr userlib.UUID, filename string) error {
	userBytes := []byte(senderUsername)
	userHash := userlib.Hash(userBytes)
	userCheck,err := userlib.UUIDFromBytes(userHash)
	if err != nil {return err}
	_,ok := userlib.DatastoreGet(userCheck)
	if !ok {return errors.New("User Doesn't Exist")}

	marshPermissionMap, ok := userlib.DatastoreGet(invitationPtr)
	if !ok{return errors.New("")}
	//Unmarshall  permissionMap
	var permissionMap map[string][]byte
	err = userlib.Unmarshal(marshPermissionMap, &permissionMap)
	if err != nil{return err}

	if marshEncNewInfo, ok := permissionMap[userdata.Username]; !ok{
		return errors.New("username not in permissionMap")
	}else{

		var encNewInfo AuthEncUser
		err = userlib.Unmarshal(marshEncNewInfo, &encNewInfo)
		if err != nil {return err}
		verifyKey,ok := userlib.KeystoreGet(senderUsername+"DS")
		if !ok{return errors.New("")}

		err = userlib.DSVerify(verifyKey,encNewInfo.EncData,encNewInfo.HMAC)
		if err != nil{return err}
		err = userlib.DSVerify(verifyKey,encNewInfo.EncryptedSymEncKey,encNewInfo.KeyHMAC)
		if err != nil{return err}

		decKey := userdata.PKEPrivKey
		Key, err := userlib.PKEDec(decKey,encNewInfo.EncryptedSymEncKey)
		if err != nil{return err}
		marshNewInfo := userlib.SymDec(Key,encNewInfo.EncData)
		var newInfo UserFileInfo
		err = userlib.Unmarshal(marshNewInfo,&newInfo)
		if err != nil{return err}

		marshEncAuthMeta, ok := userlib.DatastoreGet(newInfo.MetaUUID)
		if !ok{return errors.New("User revoked aftern invitation")}
		var authEncMeta AuthEncData
		err = userlib.Unmarshal(marshEncAuthMeta,&authEncMeta)
		if err != nil{return err}
			compar, err := userlib.HMACEval(newInfo.MetaAuthKey,authEncMeta.EncData)
			if err != nil {return err}
				if !userlib.HMACEqual(authEncMeta.HMAC,compar){
					return errors.New("User revoke after invitation")
				}


		fileInfoUUIDHASH,err := userlib.HashKDF(userdata.FatherKey[32:48],[]byte(filename))
		if err != nil{return err}
		fileInfoUUID,err := userlib.UUIDFromBytes(fileInfoUUIDHASH)
		if err != nil{return err}
		fileInfoKeys, err := userlib.HashKDF(userdata.FatherKey[16:32],[]byte(filename))
		if err != nil {return err}
		fileInfoEncKey := fileInfoKeys[0:16]
		fileInfoAuthKey := fileInfoKeys[16:32]

		_, ok = userlib.DatastoreGet(fileInfoUUID)
		if ok{return errors.New("filename already exists")}

		//marshal and encrypt, aut, marsh store, file info
		marshFileInfo, err := userlib.Marshal(newInfo)
		if err != nil{return err}
		encMarshFileInfo := userlib.SymEnc(fileInfoEncKey, userlib.RandomBytes(16), marshFileInfo)
		fileInfoHMAC, err := userlib.HMACEval(fileInfoAuthKey,encMarshFileInfo)
		if err != nil{return err}
		var authEncFileInfo AuthEncData
		authEncFileInfo.HMAC, authEncFileInfo.EncData = fileInfoHMAC, encMarshFileInfo
		marshAuthEncFileInfo, err := userlib.Marshal(authEncFileInfo)
		if err != nil{return err}
		userlib.DatastoreSet(fileInfoUUID,marshAuthEncFileInfo)

	}

	//Marshal,encrypt,authenticate,marshal and datastoreSet userStruct
	marshalUser, err := userlib.Marshal(*userdata)
	if err != nil{return errors.New("")}
	var userEncIv []byte = userlib.RandomBytes(16)
	var encMarshalUser []byte = userlib.SymEnc(userdata.EncKey, userEncIv, marshalUser)
	authUser, err := userlib.HMACEval(userdata.AuthKey,encMarshalUser)
	if err != nil{return err}
	var authEncUser AuthEncUser
	authEncUser.EncData, authEncUser.HMAC = encMarshalUser,authUser
	dataStoreUser, err := userlib.Marshal(authEncUser)
	if err != nil{return err}
	userlib.DatastoreSet(userdata.UUID,dataStoreUser)



	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	//loadFileHelper
	metaPtr, permissionMapPtr, fileInfoPtr, err := LoadFileHelper(filename, userdata,"RevokeAccess")
	if err != nil {return err}

	//loadFile
	var oldFileUUID userlib.UUID = fileInfoPtr.FileUUID
	var oldMetaUUID userlib.UUID = fileInfoPtr.MetaUUID


	//verify and decrypt filedata
	ogFile,err := userdata.LoadFile(filename)
	if err != nil {return err}



	//empty out files to be stored at oldFileUUID and oldMetaUUID
	userlib.DatastoreDelete(oldFileUUID)
	userlib.DatastoreDelete(oldMetaUUID)

	//delete user/userBranch from sharedTree
	_, ok:= metaPtr.SharedMap[recipientUsername]
	if !ok {return errors.New("not shared with user attempting to revoke")}
	delete(metaPtr.SharedTree,recipientUsername)
	for _,childRecipient := range metaPtr.SharedTree[recipientUsername]{
		delete(metaPtr.SharedTree,childRecipient)
	}
	delete(metaPtr.SharedMap,recipientUsername)

	//generate new fileSecurity info
	var fileEncKey []byte = userlib.RandomBytes(16)
	var fileAuthKey []byte = userlib.RandomBytes(16)
	var fileEncIv []byte = userlib.RandomBytes(16)
	var metaEncKey []byte = userlib.RandomBytes(16)
	var metaAuthKey []byte = userlib.RandomBytes(16)
	var metaEncIv []byte = userlib.RandomBytes(16)
	var metaUUID, fileUUID userlib.UUID = userlib.UUIDNew(), userlib.UUIDNew()

	//delete appends
	if metaPtr.AppendsListSize > 0{
	var apndUUID userlib.UUID = metaPtr.LastAppend
	for i := 0; i <metaPtr.AppendsListSize; i++ {
		marshEncApnd, ok := userlib.DatastoreGet(apndUUID)
		if !ok{return errors.New("apnd not found")}
		var encAuthApnd AuthEncData
		err = userlib.Unmarshal(marshEncApnd,&encAuthApnd)

		newHmac,err := userlib.HMACEval(fileInfoPtr.FileAuthKey,encAuthApnd.Prev)
		if err != nil{return err}
		if !userlib.HMACEqual(encAuthApnd.PrevHMAC,newHmac){return errors.New("integrity of prevAppendUUID compromised")}
		marshPrev := userlib.SymDec(fileInfoPtr.FileEncKey,encAuthApnd.Prev)
		userlib.DatastoreDelete(apndUUID)
		err = userlib.Unmarshal(marshPrev,&apndUUID)
		if err != nil{return err}
		if apndUUID.String() == userdata.UUIDNil.String(){break}


	}}
	//update metadata
	metaPtr.AppendsListSize = 0
	metaPtr.LastAppend = fileUUID

	//update fileInfoPtr
	fileInfoPtr.FileEncKey = fileEncKey
	fileInfoPtr.FileAuthKey = fileAuthKey
	fileInfoPtr.MetaEncKey = metaEncKey
	fileInfoPtr.MetaAuthKey = metaAuthKey
	fileInfoPtr.MetaUUID, fileInfoPtr.FileUUID = metaUUID, fileUUID

	fileInfoUUIDHASH,err := userlib.HashKDF(userdata.FatherKey[32:48],[]byte(filename))
	if err != nil{return err}
	fileInfoUUID,err := userlib.UUIDFromBytes(fileInfoUUIDHASH)
	if err != nil{return err}
	marshEncInfo, ok := userlib.DatastoreGet(fileInfoUUID)
	if !ok{return errors.New("fileInfo not found in datastore")}
	var authEncStruct AuthEncData
	err = userlib.Unmarshal(marshEncInfo,&authEncStruct)
	if err != nil{return err}

	fileInfoKeys, err := userlib.HashKDF(userdata.FatherKey[16:32],[]byte(filename))
	if err != nil{return err}
	fileInfoEncKey := fileInfoKeys[0:16]
	fileInfoAuthKey := fileInfoKeys[16:32]

	//marshal and encrypt, aut, marsh store, file info
	marshFileInfo, err := userlib.Marshal(*fileInfoPtr)
	if err != nil{return err}
	encMarshFileInfo := userlib.SymEnc(fileInfoEncKey, userlib.RandomBytes(16), marshFileInfo)
	fileInfoHMAC, err := userlib.HMACEval(fileInfoAuthKey,encMarshFileInfo)
	if err != nil{return err}
	var authEncFileInfo AuthEncData
	authEncFileInfo.HMAC, authEncFileInfo.EncData = fileInfoHMAC, encMarshFileInfo
	marshAuthEncFileInfo, err := userlib.Marshal(authEncFileInfo)
	if err != nil{return err}
	userlib.DatastoreSet(fileInfoUUID,marshAuthEncFileInfo)

	////loadFileHelper
	//	_, mappy,_, err := LoadFileHelper(filename, userdata, "CreateInvitation")
	//	mapy := *mappy
	//	marshed := mapy[recipientUsername]
	//	var auth AuthEncUser
	//	err = userlib.Unmarshal(marshed,&auth)
	//	if err != nil {return userlib.UUIDNew(),err}

	//new permissionMap
	permissionMap := make(map[string][]byte)
	oldPMap := *permissionMapPtr

	//iterate through shared tree
	//construct new UserFileInfo for shared users
	//secure and  store in
	for sharer,sharedArray := range metaPtr.SharedTree{
		//retrieve sharer's oldFileInfo
		marshAuthEncFileInfo := oldPMap[sharer]
		var authSharedsInfo AuthEncUser
		err = userlib.Unmarshal(marshAuthEncFileInfo,&authSharedsInfo)
		if err != nil {return errors.New("overYonder")}

		//verify and decrypt fileInfo
		decKey := userdata.PKEPrivKey
		signer := authSharedsInfo.Signer
		if !(signer == userdata.Username){return errors.New("permissionMap has been tampered with integrity compromised")}

		verifyKey,ok := userlib.KeystoreGet(userdata.Username+"DS")
		if !ok{return errors.New("signer's key not found")}

		err = userlib.DSVerify(verifyKey,authSharedsInfo.EncData,authSharedsInfo.HMAC)
		if err != nil {return err}
		err = userlib.DSVerify(verifyKey,authSharedsInfo.OwnersEncryptedKey,authSharedsInfo.OwnrEncdKeyHMAC)
		if err != nil {return err}

		Key, err := userlib.PKEDec(decKey,authSharedsInfo.OwnersEncryptedKey)
		if err != nil {return err}
		marshNewInfo := userlib.SymDec(Key,authSharedsInfo.EncData)
		var oldInfo UserFileInfo
		err = userlib.Unmarshal(marshNewInfo,&oldInfo)
		if err != nil {return err}

		//update oldInfo
		oldInfo.FileEncKey = fileEncKey
		oldInfo.FileAuthKey = fileAuthKey
		oldInfo.MetaEncKey = metaEncKey
		oldInfo.MetaAuthKey = metaAuthKey
		oldInfo.MetaUUID, oldInfo.FileUUID = metaUUID, fileUUID
		newInfo := oldInfo

		//marshal,encrypt, verify newInfo
		marshInfo, err := userlib.Marshal(newInfo)
		if err != nil {return err}
		encData := userlib.SymEnc(Key,userlib.RandomBytes(16), marshInfo)
		authSharedsInfo.EncData = encData
		hmac, err := userlib.DSSign(userdata.DSPrivKey,encData)
		if err != nil {return err}
		authSharedsInfo.HMAC = hmac

		sharedPubKey, ok := userlib.KeystoreGet(sharer+"PKE")
		if !ok {return errors.New("No key found")}
		encryptedKey, err := userlib.PKEEnc(sharedPubKey,Key)
		if err != nil {return err}
		keyHmac, err := userlib.DSSign(userdata.DSPrivKey,encryptedKey)
		if err != nil {return err}
		authSharedsInfo.EncryptedSymEncKey, authSharedsInfo.KeyHMAC = encryptedKey,keyHmac

		ownrPubKey, ok := userlib.KeystoreGet(userdata.Username+"PKE")
		if !ok {return errors.New("")}
		ownerEncdKey, err := userlib.PKEEnc(ownrPubKey,Key)
		if err != nil {return err}
		ownerEncdKeyHmac, err := userlib.DSSign(userdata.DSPrivKey,ownerEncdKey)
		if err != nil {return err}
		authSharedsInfo.Signer = userdata.Username
		authSharedsInfo.OwnersEncryptedKey = ownerEncdKey
		authSharedsInfo.OwnrEncdKeyHMAC = ownerEncdKeyHmac
		marshNewInfo, err  = userlib.Marshal(authSharedsInfo)
		if err != nil {return err}
		//store in permissonMap
		permissionMap[sharer] = marshNewInfo

		for _, shared := range sharedArray{

			//retrieve shared's oldFileInfo
			marshAuthEncFileInfo := oldPMap[shared]
			var authSharersInfo AuthEncUser
			err = userlib.Unmarshal(marshAuthEncFileInfo,&authSharersInfo)
			if err != nil {return err}

			//verify and decrypt fileInfo
			decKey := userdata.PKEPrivKey
			signer := authSharersInfo.Signer
			if _,ok = metaPtr.SharedMap[signer];!ok{return errors.New("permissionMap has been tampered with integrity compromised")}

			verifyKey,ok := userlib.KeystoreGet(signer+"DS")
			if !ok{return errors.New("")}

			err = userlib.DSVerify(verifyKey,authSharersInfo.EncData,authSharersInfo.HMAC)
			if err != nil {return err}
			err = userlib.DSVerify(verifyKey,authSharersInfo.OwnersEncryptedKey,authSharersInfo.OwnrEncdKeyHMAC)
			if err != nil {return err}

			Key, err := userlib.PKEDec(decKey,authSharersInfo.OwnersEncryptedKey)
			if err != nil {return err}
			marshNewInfo := userlib.SymDec(Key,authSharersInfo.EncData)
			var oldInfo UserFileInfo
			err = userlib.Unmarshal(marshNewInfo,&oldInfo)
			if err != nil {return err}

			//update oldInfo
			oldInfo.FileEncKey = fileEncKey
			oldInfo.FileAuthKey = fileAuthKey
			oldInfo.MetaEncKey = metaEncKey
			oldInfo.MetaAuthKey = metaAuthKey
			oldInfo.MetaUUID, oldInfo.FileUUID = metaUUID, fileUUID
			newInfo := oldInfo

			//marshal,encrypt, verify newInfo
			marshInfo, err := userlib.Marshal(newInfo)
			if err != nil {return err}
			encData := userlib.SymEnc(Key,userlib.RandomBytes(16), marshInfo)
			authSharersInfo.EncData = encData
			hmac, err := userlib.DSSign(userdata.DSPrivKey,encData)
			if err != nil {return err}
			authSharersInfo.HMAC = hmac

			sharedPubKey, ok := userlib.KeystoreGet(shared+"PKE")
			if !ok {return errors.New("")}
			encryptedKey, err := userlib.PKEEnc(sharedPubKey,Key)
			if err != nil {return err}
			keyHmac, err := userlib.DSSign(userdata.DSPrivKey,encryptedKey)
			if err != nil {return err}
			authSharersInfo.EncryptedSymEncKey, authSharersInfo.KeyHMAC = encryptedKey,keyHmac

			ownrPubKey, ok := userlib.KeystoreGet(userdata.Username+"PKE")
			if !ok {return errors.New("")}
			ownerEncdKey, err := userlib.PKEEnc(ownrPubKey,Key)
			if err != nil {return err}
			ownerEncdKeyHmac, err := userlib.DSSign(userdata.DSPrivKey,ownerEncdKey)
			if err != nil {return err}
			authSharersInfo.Signer = userdata.Username
			authSharersInfo.OwnersEncryptedKey = ownerEncdKey
			authSharersInfo.OwnrEncdKeyHMAC = ownerEncdKeyHmac
			marshNewInfo, err  = userlib.Marshal(authSharersInfo)
			if err != nil {return err}
			//store in permissonMap
			permissionMap[shared] = marshNewInfo
		}




	}

	//secure, serialize and store user struct
	//secure, serialize and store permission map
	//secure, serialize and store file with new keys, and uuid
	//secure, serialize and store metadata w/ new keys and uuid
	//go back to loadfile helper and make sure old revoked files are delete instead of empty structs when check file location
	//Marshal,encrypt,authenticate,marshal and datastoreSet metadata
	marshalMeta, err := userlib.Marshal(*metaPtr)
	if err != nil {return err}
	var encMarshalMeta []byte = userlib.SymEnc(metaEncKey, metaEncIv, marshalMeta)
	authMeta, err := userlib.HMACEval(metaAuthKey,encMarshalMeta)
	if err != nil{return err}
	var authEncMeta AuthEncData
	authEncMeta.EncData, authEncMeta.HMAC = encMarshalMeta,authMeta
	dataStoreMeta, err := userlib.Marshal(authEncMeta)
	if err != nil {return err}
	userlib.DatastoreSet(metaUUID,dataStoreMeta)

	//Marshal,encrypt,authenticate,marshal and datastoreSet file
	marshalFile, err := userlib.Marshal(ogFile)
	if err != nil{return err}
	var encMarshalFile []byte = userlib.SymEnc(fileEncKey, fileEncIv, marshalFile)
	authFile, err := userlib.HMACEval(fileAuthKey,encMarshalFile)
	if err != nil {return err}
	marshalUUID, err := userlib.Marshal(userdata.UUIDNil)
	if err != nil{return err}
	var encMarshUUID []byte = userlib.SymEnc(fileEncKey,userlib.RandomBytes(16), marshalUUID)
	authUUID, err := userlib.HMACEval(fileAuthKey,encMarshUUID)
	if err != nil {return err}
	var AuthEncData AuthEncData
	AuthEncData.EncData, AuthEncData.HMAC = encMarshalFile,authFile
	AuthEncData.Prev,AuthEncData.PrevHMAC = encMarshUUID,authUUID
	dataStoreFile, err := userlib.Marshal(AuthEncData)
	if err != nil {return err}
	userlib.DatastoreSet(fileUUID,dataStoreFile)

	//Marshal,encrypt,authenticate,marshal and datastoreSet userStruct
	marshalUser, err := userlib.Marshal(*userdata)
	if err != nil {return err}
	var userEncIv []byte = userlib.RandomBytes(16)
	var encMarshalUser []byte = userlib.SymEnc(userdata.EncKey, userEncIv, marshalUser)
	authUser, err := userlib.HMACEval(userdata.AuthKey,encMarshalUser)
	if err != nil {return err}
	var authEncUser AuthEncUser
	authEncUser.EncData, authEncUser.HMAC = encMarshalUser,authUser
	dataStoreUser, err := userlib.Marshal(authEncUser)
	if err != nil {return err}
	userlib.DatastoreSet(userdata.UUID,dataStoreUser)

	//Marshal and datastoreSet permissionMap
	marshalPMap, err := userlib.Marshal(permissionMap)
	if err != nil {return err}
	userlib.DatastoreSet(fileInfoPtr.PermissionMapUUID,marshalPMap)


	return nil
}